"""Real-process defensive patch regression across pinned HTTP server builds.

Inputs are ordinary functional requests. Per-case reports distinguish bytecode
proofs from source coverage obligations and measured feature regressions.
"""
import argparse
import copy
from contextlib import ExitStack
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time
import traceback
import random
import urllib.parse

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT))
from experiments.postdeploy.benchmark20.bindings import BUILD, artifact, layout, symbols
from experiments.postdeploy.benchmark20.network import Backend, ServerWorker, TEXT, RANGE
from tools.postdeploy.expressions import compile_guard
from tools.postdeploy.monitors import VMReplay
from tools.postdeploy.coverage import summarize
from tools.postdeploy.symbolic import prove_vm_summary

CBMC=Path('/mnt/d/Codex/2026-11-03/goal-042fb9fb-01ec-4a00-960b-c95a63665f9e/work/general-implementation/reproducible-toolchain-v3/cbmc/usr/bin/cbmc')
CASES={
 'CVE-2026-93479':('nginx-1.31.6','script'),
 'CVE-2026-97205':('nginx-1.31.6','aio'),
 'CVE-2026-15176':('nginx-1.31.6','alias'),
 'CVE-2026-42533':('nginx-1.29.6','map'),
 'CVE-2026-60005':('nginx-1.29.6','captures'),
 'CVE-2026-9256':('nginx-1.31.0','rewrite'),
 'CVE-2026-42945':('nginx-1.29.6','rewrite'),
 'CVE-2026-42055':('nginx-1.29.6','h2proxy'),
 'CVE-2026-27654':('nginx-1.29.6','dav'),
 'CVE-2026-63292':('httpd-2.4.68','vhost'),
 'CVE-2026-57941':('httpd-2.4.68','h2'),
 'CVE-2026-93546':('httpd-2.4.68','davprop'),
 'CVE-2026-47360':('httpd-2.4.68','sessionproxy'),
 'CVE-2026-63686':('httpd-2.4.68','xml'),
 'CVE-2026-56153':('httpd-2.4.68','charset'),
 'CVE-2026-56449':('httpd-2.4.68','comments'),
 'CVE-2026-56154':('httpd-2.4.68','lookahead'),
}


def read(arg, *steps):
    return {'arg':arg,'reads':[{'offset':offset,'type':kind} for offset,kind in steps]}


def policies(name,kind):
    offsets=layout(name); target=artifact(name); sym=symbols(target)
    guards=[]
    def guard(function,args,ret,expression='True',sources=None,action=None,module=None):
        path=artifact(name,module) if module else target
        names=symbols(path) if module else sym
        if function not in names: raise ValueError('missing/ambiguous symbol: '+function)
        fields={key:{'source':'arg','index':i} for i,key in enumerate(sources or {})}
        entry={'id':function,'module':path.name,'offset':names[function], 'arg_types':args,
               'return_type':ret,'action_id':function+'_error', 'vm_args':list((sources or {}).values()),
               'expression':expression,'fields':fields,'artifact':str(path),
               'catalog_action':action or {'kind':'return_int','value':-1}}
        guards.append(entry)
    if kind=='script':
        action={'kind':'return_int','value':-1,'writes':[
            {'arg':0,'offset':offsets['ngx_http_script_engine_t.ip'],'type':'pointer',
             'symbol':{'module':target.name,'offset':sym['ngx_http_script_exit_code']}},
            {'arg':0,'offset':offsets['ngx_http_script_engine_t.status'],'type':'u64','value':500}]}
        guard('ngx_http_script_check_length',['pointer','uint64'],'int64','length != 0',
              {'length':{'arg':1,'type':'uint64'}},action)
    elif kind=='aio':
        bit=offsets['bit.blocked']; unit=bit['mask'] & -bit['mask']
        guard('ngx_http_copy_filter',['pointer','pointer'],'int64',f'(counter & {bit["mask"]}) >= {250*unit}',
              {'counter':read(0,(offsets['ngx_http_request_t.main'],'pointer'),(bit['offset'],'u32'))})
    elif kind=='alias':
        bit=offsets['bit.uri_changed']
        guard('ngx_http_map_uri_to_path',['pointer','pointer','pointer','uint64'],'pointer',
              f'alias != 0 and (flags & {bit["mask"]}) != 0',
              {'alias':read(0,(offsets['ngx_http_request_t.loc_conf'],'pointer'),(0,'pointer'),
                            (offsets['ngx_http_core_loc_conf_t.alias'],'u64')),
               'flags':read(0,(bit['offset'],'u32'))}, {'kind':'return_null'})
        guards[-1]['vm_args'][0]['reads'][1].update(index={'global':{
            'module':target.name,'offset':sym['ngx_http_core_module']},
            'reads':[{'offset':offsets['ngx_module_t.ctx_index'],'type':'u64'}]},stride=8)
    elif kind=='map':
        guard('ngx_http_map_variable',['pointer','pointer','uint64'],'int64')
    elif kind=='captures':
        bit=offsets['bit.realloc_captures']
        guard('ngx_http_regex_exec',['pointer','pointer','pointer'],'int64',
              f'captures != 0 and (flags & {bit["mask"]}) != 0',
              {'captures':read(0,(offsets['ngx_http_request_t.ncaptures'],'u64')),
               'flags':read(0,(bit['offset'],'u32'))})
    elif kind=='rewrite':
        guard('ngx_http_script_regex_start_code',['pointer'],'void',action={'kind':'return_void','writes':[
            {'arg':0,'offset':offsets['ngx_http_script_engine_t.ip'],'type':'pointer',
             'symbol':{'module':target.name,'offset':sym['ngx_http_script_exit_code']}},
            {'arg':0,'offset':offsets['ngx_http_script_engine_t.status'],'type':'u64','value':500}]})
    elif kind=='h2proxy':
        for function in ['ngx_http_proxy_v2_create_request','ngx_http_grpc_create_request']:
            guard(function,['pointer'],'int64')
    elif kind=='dav':
        guard('ngx_http_dav_copy_move_handler',['pointer'],'int64',action={'kind':'return_int','value':405})
    elif kind=='vhost':
        guard('mva_translate',['pointer'],'int',action={'kind':'return_int','value':414},module='mod_vhost_alias.so')
    elif kind=='h2':
        guard('h2_c1_setup',['pointer','pointer','pointer'],'int',action={'kind':'return_int','value':20014},module='mod_http2.so')
    elif kind=='davprop':
        guard('dav_method_proppatch',['pointer'],'int',action={'kind':'return_int','value':503},module='mod_dav.so')
    elif kind=='sessionproxy':
        guard('proxy_handler',['pointer'],'int','previous != 0',
              {'previous':read(0,(offsets['request_rec.prev'],'pointer'))},
              {'kind':'return_int','value':503},module='mod_proxy.so')
    elif kind=='xml':
        guard('xml2enc_ffunc',['pointer','pointer'],'int',action={'kind':'return_int','value':20014},module='mod_xml2enc.so')
    elif kind=='charset':
        guard('xlate_out_filter',['pointer','pointer'],'int',action={'kind':'return_int','value':20014},module='mod_charset_lite.so')
    elif kind=='comments':
        guard('pcomment',['pointer','pointer'],'void',action={'kind':'return_void'},module='mod_proxy_html.so')
    elif kind=='lookahead':
        guard('lookup_variable',['pointer','pointer'],'pointer',action={'kind':'return_string','value':''},module='mod_rewrite.so')
    return guards


def nginx_config(root,port,backend,kind):
    data=root/'www'; data.mkdir(exist_ok=True)
    (data/'file.txt').write_bytes(b'ordinary file\n'*512)
    (data/'source.txt').write_bytes(b'ordinary DAV file\n')
    (data/'dynamic').mkdir(exist_ok=True)
    (data/'dynamic/file.txt').write_bytes(b'ordinary dynamic root\n')
    return f'''daemon off;
master_process off;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 128; }}
http {{
 access_log off;
 client_body_temp_path {root}/body;
 proxy_temp_path {root}/proxy;
 fastcgi_temp_path {root}/fastcgi;
 uwsgi_temp_path {root}/uwsgi;
 scgi_temp_path {root}/scgi;
 map $uri $ordinary_map {{ default ordinary; ~^/map/(.*)$ mapped; }}
 server {{
  listen 127.0.0.1:{port}; server_name localhost;
  root {data};
  location = /plain {{ return 200 'healthy'; }}
  location = /value {{ return 200 'value=$arg_name'; }}
  location /map/ {{ return 200 $ordinary_map; }}
  location /rewrite/ {{ rewrite ^/rewrite/(.*)$ /plain redirect; }}
  location /files/ {{ alias {data}/; aio threads; sendfile off; }}
  location /dynamic/ {{ root {root}/$arg_dir; }}
  location /slice {{ slice 512; proxy_set_header Range $slice_range; proxy_pass http://127.0.0.1:{backend}/range; }}
  location /h2proxy {{ proxy_http_version 2; proxy_pass http://127.0.0.1:{backend}/plain; }}
  location /grpc {{ grpc_pass grpc://127.0.0.1:{backend}; }}
  location /dav/ {{ root {root}; dav_methods PUT DELETE MKCOL COPY MOVE; create_full_put_path on; }}
 }}
}}
'''


def httpd_config(name,root,port,backend,kind):
    data=root/'www'; data.mkdir(exist_ok=True)
    (data/'plain.txt').write_text('healthy')
    (data/'success.txt').write_text('condition matched')
    (data/'latin.txt').write_bytes(b'caf\xe9\n')
    dav=root/'dav'; dav.mkdir(exist_ok=True); (dav/'file.txt').write_text('ordinary DAV file')
    required=['authn_core','authn_file','authz_core','authz_host','authz_user','auth_basic','unixd','log_config',
        'mime','dir','alias','headers','filter','proxy','proxy_http','xml2enc','proxy_html','charset_lite',
        'rewrite','session','session_cookie','dav','dav_fs','vhost_alias','http2']
    loads=[]
    for module in required:
        candidates=list(Path(json.loads((BUILD/name/'build.json').read_text())['source']).glob('modules/**/.libs/mod_'+module+'.so'))
        if not candidates:
            if module in ['unixd','log_config']: continue
            raise ValueError('missing module '+module)
        loads.append(f'LoadModule {module}_module {candidates[0]}')
    extra=''
    if kind=='vhost': extra=f'VirtualDocumentRoot {data}\n'
    if kind=='sessionproxy': extra += 'ErrorDocument 404 /proxy/plain\n'
    return '\n'.join(loads)+f'''
ServerRoot {root}
PidFile {root}/httpd.pid
Listen 127.0.0.1:{port}
ServerName localhost
ErrorLog {root}/error.log
LogLevel warn
User vita
Group vita
StartServers 1
ServerLimit 1
ThreadsPerChild 4
MaxRequestWorkers 4
Protocols h2c http/1.1
H2Direct on
TypesConfig /tmp/vulgate-benchmark20-20261112/{name}/docs/conf/mime.types
DocumentRoot {data}
<Directory {root}>
 Require all granted
 Options FollowSymLinks
</Directory>
{extra}
Alias /dav/ {dav}/
DavLockDB {root}/davlocks
<Location /dav/>
 Dav On
</Location>
ProxyPass /proxy/ http://127.0.0.1:{backend}/
ProxyPass /html http://127.0.0.1:{backend}/html
<Location /html>
 ProxyHTMLEnable On
 SetOutputFilter proxy-html
 ProxyHTMLStripComments Off
 ProxyHTMLLinks a href
 ProxyHTMLDocType XHTML
 ProxyHTMLURLMap /old /new
</Location>
<Location /latin.txt>
 CharsetSourceEnc ISO-8859-1
 CharsetDefault UTF-8
 SetOutputFilter CHARSET_LITE
</Location>
RewriteEngine On
RewriteRule ^/redirect$ /proxy/plain [PT,L]
RewriteCond %{{HTTP_USER_AGENT}} ordinary
RewriteRule ^/condition$ /success.txt [PT,L]
'''


def corpus(kind,root):
    root.mkdir(exist_ok=True)
    def case(name,path,method='GET',body=None,headers=None,expected=200,protocol=None):
        req={'method':method,'path':path,'headers':headers or {},'response_kind':'http'}
        if body is not None:
            path_file=root/(name+'.body'); path_file.write_bytes(body); req['body_file']=str(path_file)
        if protocol: req['protocol']=protocol
        return {'id':name,'request':req,'expected_status':expected}
    if kind in ['script','aio','alias','map','captures','rewrite','h2proxy','dav']:
        result=[case('plain','/plain'),case('value','/value?name=ordinary'),case('file','/files/file.txt')]
        extra={'script':[case('dynamic_root','/dynamic/file.txt?dir=www')],
               'aio':[], 'alias':[], 'map':[case('map','/map/ordinary')],
               'captures':[case('regex','/map/ordinary'),case('slice','/slice')],
               'rewrite':[case('rewrite','/rewrite/ordinary',expected=302)],
               'h2proxy':[case('proxy_http2','/h2proxy'),case('grpc','/grpc')],
               'dav':[case('copy','/dav/source.txt','COPY',headers={'Destination':'/dav/copy.txt'},expected=204)]}
        return result+extra[kind]
    result=[case('plain','/plain.txt'),case('proxy','/proxy/plain')]
    if kind=='h2': result += [case('http2','/plain.txt',protocol='h2')]
    elif kind=='davprop':
        result += [case('proppatch','/dav/file.txt','PROPPATCH',
            b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:X="urn:ordinary"><D:set><D:prop><X:label>hello</X:label></D:prop></D:set></D:propertyupdate>',
            {'Content-Type':'application/xml'},207)]
    elif kind=='sessionproxy': result += [case('redirect','/missing-internal-redirect')]
    elif kind in ['xml','comments']: result += [case('html','/html')]
    elif kind=='charset': result += [case('latin','/latin.txt')]
    elif kind=='lookahead': result += [case('condition','/condition',headers={'User-Agent':'ordinary'})]
    return result


def functional_corpus(kind,directory):
    base=corpus(kind,directory)
    randomizer=random.Random(20261113)
    for item in base:
        yield item
        for index,length in enumerate([1,17,129]):
            derived=copy.deepcopy(item)
            derived['id']=item['id']+'-ordinary-'+str(index)
            token=''.join(randomizer.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(length))
            request=derived['request']; request['headers']['X-Ordinary-Token']=token
            request['path'] += ('&' if '?' in request['path'] else '?')+'sample='+token
            if item['id']=='value': request['path']='/value?name='+urllib.parse.quote(token)
            yield derived


def run(identifier,output,backend):
    name,kind=CASES[identifier]
    reference='nginx-1.31.7' if name.startswith('nginx') else 'httpd-2.4.71'
    output.mkdir(parents=True,exist_ok=False)
    guards=policies(name,kind)
    actions={g['action_id']:g['catalog_action'] for g in guards}
    manifest={'schema':1,'bridge':str(ROOT/'build/frida-linux/vulgate_frida.so'),'telemetry':True,
              'maps':{},'observers':[],'guards':[],'artifact_pins':{}}
    for index,g in enumerate(guards):
        code=output/f'guard-{index}.bin'; code.write_bytes(compile_guard(g['expression'],g['fields']))
        spec={k:v for k,v in g.items() if k not in ['expression','fields','artifact','catalog_action']}
        spec['rule']=str(code); manifest['guards'].append(spec)
        manifest['artifact_pins'][g['artifact']]=hashlib.sha256(Path(g['artifact']).read_bytes()).hexdigest()
    patch,catalog=output/'patch.json',output/'actions.json'
    patch.write_text(json.dumps(manifest,indent=2)); catalog.write_text(json.dumps({'schema':1,'actions':actions},indent=2))
    (output/'policy-source.json').write_text(json.dumps(guards,indent=2))
    proofs=[]
    for index,g in enumerate(guards):
        proofs.append(prove_vm_summary({'expression':g['expression'],'fields':g['fields']},
            {'rule_path':manifest['guards'][index]['rule']},
            {'cbmc':str(CBMC),'timeout':90,'unwind':10},output/f'vm-proof-{index}'))
    if any(p['status']!='unsat' for p in proofs): raise RuntimeError('VM summary unresolved')
    results=[]; pairs=[]; total={'decisions':0,'blocks':0,'diagnostics':0}
    begin=time.monotonic()
    with ExitStack() as stack:
        workers={}
        for world in ['baseline','patched','reference']:
            version=reference if world=='reference' else name
            directory=output/world; directory.mkdir()
            if name.startswith('nginx'):
                (directory/'dav').mkdir(); (directory/'dav/source.txt').write_text('ordinary DAV file\n')
                command=[str(artifact(version)),'-p',str(directory)+'/', '-c',str(directory/'server.conf')]
                prepare=lambda port,d=directory: (d/'server.conf').write_text(nginx_config(d,port,backend,kind))
            else:
                command=[str(artifact(version)),'-X','-f',str(directory/'server.conf')]
                prepare=lambda port,d=directory,v=version: (d/'server.conf').write_text(httpd_config(v,d,port,backend,kind))
            trace={'module':artifact(version).name,'anchor_offset':symbols(artifact(version))['main']}
            workers[world]=stack.enter_context(ServerWorker(command,directory,trace,
                patch=patch if world=='patched' else None,catalog=catalog,prepare=prepare,timeout=12))
        vm=VMReplay(manifest['bridge'],{g['id']:{'path':Path(g['rule']),'observations':[]} for g in manifest['guards']})
        stack.callback(vm.close)
        for case in functional_corpus(kind,output/'corpus'):
            executions={world:worker.execute(case['request']) for world,worker in workers.items()}
            outcomes={world:execution['outcome'] for world,execution in executions.items()}
            replay=vm.check(executions['patched']['events'])
            if replay['violations']: raise AssertionError(replay['violations'])
            for key in total: total[key]+=replay[key]
            baseline=outcomes['baseline']; patched=outcomes['patched']; fixed=outcomes['reference']
            eligible=all(o['http_status']==case['expected_status'] and o['response_complete'] for o in [baseline,fixed])
            fields=['http_status','response_complete'] + (['body_sha256'] if case['expected_status']==200 else [])
            changed=[key for key in fields if baseline.get(key)!=patched.get(key)]
            reference_diff=[key for key in fields if baseline.get(key)!=fixed.get(key)]
            pairs.append((case['id'],baseline,patched))
            with gzip.open(output/(case['id']+'.json.gz'),'wt') as file:
                json.dump({'case':case,'executions':executions,'replay':replay},file)
            results.append({'id':case['id'],'eligible_normal_case':eligible,'changed_fields':changed,
                'reference_difference':reference_diff,'blocks':replay['blocks'],
                'outcomes':{world:{k:v for k,v in o.items() if k!='trace'} for world,o in outcomes.items()}})
            print(json.dumps({'id':identifier,'case':case['id'],'eligible':eligible,'changed':changed,'blocks':replay['blocks']}),flush=True)
    coverage=summarize(pairs)
    report={'id':identifier,'baseline':name,'reference':reference,'variant':kind,
        'seconds_native':time.monotonic()-begin,'vm_proofs':proofs,'monitor':total,
        'cases':results,'coverage':{k:v for k,v in coverage.items() if k not in ['paths','edge_tests']},
        'normal_cases':sum(r['eligible_normal_case'] and not r['reference_difference'] for r in results),
        'affected_normal_cases':sum(r['eligible_normal_case'] and not r['reference_difference'] and bool(r['changed_fields']) for r in results),
        'native_hook_exercised':total['decisions']>0,
        'all_normal_controls_pass':all(r['eligible_normal_case'] for r in results),
        'sufficiency':{'whole_vulnerability_proved':False,'vm_predicate_equivalence':True,
            'scope':'installed guard and declared return action; whole-program coverage and action/continuation proof remain separate obligations'},
        'source_hashes':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),HERE/'network.py',
            ROOT/'runtime/frida/agent.js',ROOT/'runtime/vm.c',ROOT/'tools/postdeploy/expressions.py',
            ROOT/'tools/postdeploy/http_process.py']}}
    (output/'coverage.json').write_text(json.dumps(coverage,indent=2))
    (output/'report.json').write_text(json.dumps(report,indent=2))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cases',nargs='*',default=list(CASES))
    args=parser.parse_args(); args.output=args.output.resolve(); args.output.mkdir(parents=True,exist_ok=True)
    reports=[]
    with Backend() as backend:
        for identifier in args.cases:
            try: reports.append(run(identifier,args.output/identifier,backend.port))
            except Exception as error:
                traceback.print_exc()
                result={'id':identifier,'error':str(error),'type':type(error).__name__}
                reports.append(result)
                (args.output/(identifier+'.error.json')).write_text(json.dumps(result,indent=2))
            (args.output/'summary.json').write_text(json.dumps(reports,indent=2))
