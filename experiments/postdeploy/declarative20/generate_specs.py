from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
import traceback
from typing import Any
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))

from experiments.postdeploy.benchmark20.bindings import BUILD, artifact, layout, symbols
from tools.postdeploy.evaluate import evaluate_case
from tools.postdeploy.oracle_compiler import CASE_ORACLE_BINDINGS


def _write_yaml(path: Path, data: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding='utf-8')
    return path


def _nginx_conf_template() -> str:
    return '''daemon off;
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
  root {root}/www;
  location = /plain {{ return 200 'healthy'; }}
  location = /value {{ return 200 'value=$arg_name'; }}
  location /map/ {{ return 200 $ordinary_map; }}
  location /rewrite/ {{ rewrite ^/rewrite/(.*)$ /plain redirect; }}
  location /files/ {{ alias {root}/www/; aio threads; sendfile off; }}
  location /dynamic/ {{ root {root}/$arg_dir; }}
  location /slice {{ slice 512; proxy_set_header Range $slice_range; proxy_pass http://127.0.0.1:{backend}/range; }}
  location /h2proxy {{ proxy_http_version 2; proxy_pass http://127.0.0.1:{backend}/plain; }}
  location /grpc {{ grpc_pass grpc://127.0.0.1:{backend}; }}
  location /dav/ {{ root {root}; dav_methods PUT DELETE MKCOL COPY MOVE; create_full_put_path on; }}
 }}
}}
'''


def _httpd_conf_template(extra: str = '') -> str:
    return '''{module_loads}
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
TypesConfig {source_dir}/docs/conf/mime.types
DocumentRoot {root}/www
<Directory {root}>
 Require all granted
 Options FollowSymLinks
</Directory>
''' + extra + '''
Alias /dav/ {root}/dav/
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


def _nginx_script_capture_conf() -> str:
    text = _nginx_conf_template()
    text = text.replace(
        ' map $uri $ordinary_map {{ default ordinary; ~^/map/(.*)$ mapped; }}',
        ' map $uri $ordinary_map {{ default ordinary; ~^/map/(.*)$ mapped; }}\n'
        ' map $uri $mapped {{ ~^/m/(?<cap>.*)$ $cap; default ""; }}',
        1,
    )
    text = text.replace(
        ' location /dynamic/ {{ root {root}/$arg_dir; }}',
        ' location /dynamic/ {{ root {root}/$arg_dir; }}\n'
        ' location /m/ {{ root {root}/www/$cap$mapped; }}',
        1,
    )
    return text


def _script_capture_poc() -> dict[str, Any]:
    return {
        'invocation_selector': 'last_before_fault',
        'requests': [
            {'method': 'GET', 'uri': '/m/file.txt'},
            {'method': 'GET', 'uri': '/m/' + ('A' * 4000)},
        ],
    }


def _nginx_alias_rewrite_conf() -> str:
    return _nginx_conf_template().replace(
        ' location /dynamic/ {{ root {root}/$arg_dir; }}',
        ' location /dynamic/ {{ root {root}/$arg_dir; }}\n'
        ' location /a-very-long-prefix/ {{\n'
        '  alias {root}/www/;\n'
        '  rewrite ^/a-very-long-prefix/(.*)$ /$1;\n'
        '  set $fn $request_filename;\n'
        '  return 200 "fn=$fn\\n";\n'
        ' }}',
        1,
    )


def _alias_rewrite_poc() -> dict[str, Any]:
    return {
        'invocation_selector': 'last_before_fault',
        'requests': [{'method': 'GET', 'uri': '/a-very-long-prefix/file.txt'}],
    }


def _nginx_dav_alias_conf() -> str:
    return _nginx_conf_template().replace(
        ' location /dav/ {{ root {root}; dav_methods PUT DELETE MKCOL COPY MOVE; create_full_put_path on; }}',
        ' location /dav/ {{ alias {root}/www/really-long-directory-name/; dav_methods PUT DELETE MKCOL COPY MOVE; create_full_put_path on; }}',
        1,
    )


def _dav_short_destination_poc() -> dict[str, Any]:
    return {
        'invocation_selector': 'last_before_fault',
        'requests': [{
            'method': 'COPY',
            'uri': '/dav/poc-src.txt',
            'headers': {'Destination': '/dav', 'Overwrite': 'T', 'Depth': 'infinity'},
        }],
    }


def _nginx_isargs_conf() -> str:
    return _nginx_conf_template().replace(
        ' location /dav/ {{ root {root}; dav_methods PUT DELETE MKCOL COPY MOVE; create_full_put_path on; }}',
        ' location /dav/ {{ root {root}; dav_methods PUT DELETE MKCOL COPY MOVE; create_full_put_path on; }}\n'
        ' location / {{\n'
        '  rewrite ^(.*) /new?c=1;\n'
        '  set $myvar $1;\n'
        '  return 200 $myvar;\n'
        ' }}',
        1,
    )


def _isargs_poc() -> dict[str, Any]:
    return {
        'invocation_selector': 'last_before_fault',
        'requests': [
            {'method': 'GET', 'uri': '/a%25b'},
            {'method': 'GET', 'uri': '/' + ('%25' * 1000)},
        ],
    }


def _nginx_std_files() -> dict[str, str]:
    return {
        'www/file.txt': 'ordinary file\n' * 512,
        'www/source.txt': 'ordinary DAV file\n',
        'www/dynamic/file.txt': 'ordinary dynamic root\n',
        'dav/source.txt': 'ordinary DAV file\n',
    }


def _httpd_std_files() -> dict[str, Any]:
    return {
        'www/plain.txt': 'healthy',
        'www/success.txt': 'condition matched',
        'www/latin.txt': list(b'caf\xe9\n'),
        'dav/file.txt': 'ordinary DAV file',
    }


def _nginx_base_seeds(extra: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    base = [
        {'id': 'plain', 'group': 'static_http', 'method': 'GET', 'path': '/plain', 'expected_status': 200},
        {'id': 'value', 'group': 'script_variable', 'method': 'GET', 'path': '/value?name=ordinary', 'expected_status': 200},
        {'id': 'file', 'group': 'static_alias_aio', 'method': 'GET', 'path': '/files/file.txt', 'expected_status': 200},
    ]
    return base + (extra or [])


def _httpd_base_seeds(extra: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    base = [
        {'id': 'plain', 'group': 'static_http', 'method': 'GET', 'path': '/plain.txt', 'expected_status': 200},
        {'id': 'proxy', 'group': 'reverse_proxy', 'method': 'GET', 'path': '/proxy/plain', 'expected_status': 200},
    ]
    return base + (extra or [])


def lifecycle_hooks_for(family: str) -> dict[str, Any]:
    if family == 'nginx':
        return {
            'quiescent_attach': 'pre_first_request',
            'operation_begin': ['ngx_http_process_request', 'ngx_http_core_run_phases'],
            'operation_end': ['ngx_http_finalize_request'],
            'request_reset': 'process_restart',
        }
    if family == 'httpd':
        return {
            'quiescent_attach': 'pre_first_request',
            'operation_begin': ['ap_process_request_internal', 'ap_invoke_handler', 'ap_pass_brigade'],
            'operation_end': ['ap_process_request'],
            'request_reset': 'process_restart',
            'between_requests': 'apr_pool_clear',
        }
    if family == 'php':
        return {
            'quiescent_attach': 'pre_first_request',
            'operation_begin': ['php_request_startup', 'sapi_handle_post'],
            'operation_end': ['php_request_shutdown'],
            'request_reset': 'request_cleanup_then_snapshot',
            'between_requests': 'php_request_shutdown',
        }
    if family == 'brotli':
        return {
            'quiescent_attach': 'pre_first_request',
            'operation_begin': ['BrotliDecoderDecompressStream'],
            'operation_end': ['BrotliDecoderDecompressStream'],
            'request_reset': 'process_restart',
        }
    raise KeyError(family)


def generate_app_profiles(spec_root: Path) -> dict[str, Path]:
    profiles_dir = spec_root / 'app_profiles'
    profiles_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    for ver in ('nginx-1.29.6', 'nginx-1.31.0', 'nginx-1.31.6'):
        b_json = json.loads((BUILD / ver / 'build.json').read_text(encoding='utf-8'))
        src_dir = Path(b_json['source'])
        ngx_lay = layout(ver)
        inc_dirs = [str(src_dir / sub) for sub in (
            'src/core', 'src/event', 'src/event/modules', 'src/os/unix',
            'src/http', 'src/http/modules', 'src/http/v2', 'src/stream', 'objs',
        )]
        prof = {
            'schema': 'vulgate.app_profile/v2',
            'name': ver,
            'family': 'nginx',
            'protocol': 'nginx_http',
            'bridge': str(ROOT / 'build/frida-linux/vulgate_frida.so'),
            'operation_roots': ['ngx_http_process_request', 'ngx_http_core_run_phases'],
            'lifecycle_hooks': lifecycle_hooks_for('nginx'),
            'builds': {
                'baseline': {
                    'executable': str(artifact(ver)),
                    'source_dir': str(src_dir),
                },
                'reference': {
                    'executable': str(artifact('nginx-1.31.7')),
                    'source_dir': str(json.loads((BUILD / 'nginx-1.31.7/build.json').read_text(encoding='utf-8'))['source']),
                },
            },
            'layout': ngx_lay,
            'symbolic_slice': {
                'include_dirs': inc_dirs,
                'defines': ['_GNU_SOURCE'],
                'helper_includes': ['<ngx_config.h>', '<ngx_core.h>', '<ngx_http.h>'],
            },
            'pointer_arrays': [
                {
                    'field': 'main_conf',
                    'count_symbol': 'ngx_http_max_module',
                    'slot_index_symbol': 'ngx_http_core_module.ctx_index',
                    'slot_type': 'ngx_http_core_main_conf_t',
                    'max_count': 64,
                },
                {
                    'field': 'srv_conf',
                    'count_symbol': 'ngx_http_max_module',
                    'slot_index_symbol': 'ngx_http_core_module.ctx_index',
                    'slot_type': 'ngx_http_core_srv_conf_t',
                    'max_count': 64,
                },
                {
                    'field': 'loc_conf',
                    'count_symbol': 'ngx_http_max_module',
                    'slot_index_symbol': 'ngx_http_core_module.ctx_index',
                    'slot_type': 'ngx_http_core_loc_conf_t',
                    'max_count': 64,
                },
            ],
            'action_catalog': {
                'NGX_ERROR_RETURN': {'kind': 'return_int', 'value': -1},
                'NGX_NULL_RETURN': {'kind': 'return_null'},
                'NGX_HTTP_405_RETURN': {'kind': 'return_int', 'value': 405},
                'NGX_SCRIPT_EXIT_INT_ERROR': {
                    'kind': 'return_int',
                    'value': -1,
                    'writes': [
                        {'arg': 0, 'struct_member': ['ngx_http_script_engine_t', 'ip'], 'type': 'pointer', 'symbol_name': 'ngx_http_script_exit_code'},
                        {'arg': 0, 'struct_member': ['ngx_http_script_engine_t', 'status'], 'type': 'u64', 'value': 500},
                    ],
                },
                'NGX_SCRIPT_EXIT_VOID_ERROR': {
                    'kind': 'return_void',
                    'writes': [
                        {'arg': 0, 'struct_member': ['ngx_http_script_engine_t', 'ip'], 'type': 'pointer', 'symbol_name': 'ngx_http_script_exit_code'},
                        {'arg': 0, 'struct_member': ['ngx_http_script_engine_t', 'status'], 'type': 'u64', 'value': 500},
                    ],
                },
            },
        }
        paths[ver] = _write_yaml(profiles_dir / f'{ver}.yaml', prof)

    httpd_b = json.loads((BUILD / 'httpd-2.4.68/build.json').read_text(encoding='utf-8'))
    httpd_ref_b = json.loads((BUILD / 'httpd-2.4.71/build.json').read_text(encoding='utf-8'))
    httpd_src = Path(httpd_b['source'])
    httpd_inc = [
        str(httpd_src / 'include'),
        str(httpd_src / 'os/unix'),
        str(httpd_src / 'server'),
        str(httpd_src / 'modules/dav/main'),
        str(httpd_src / 'modules/proxy'),
        str(httpd_src / 'modules/filters'),
        str(httpd_src / 'modules/http2'),
        str(httpd_src / 'modules/session'),
        str(httpd_src / 'modules/mappers'),
        str(httpd_src / 'modules/generators'),
        str(httpd_src / 'modules/database'),
        str(httpd_src / 'modules/ssl'),
        '/usr/include/apr-1.0',
        '/usr/include/libxml2',
    ]
    httpd_prof = {
        'schema': 'vulgate.app_profile/v2',
        'name': 'httpd-2.4.68',
        'family': 'httpd',
        'protocol': 'httpd_http',
        'bridge': str(ROOT / 'build/frida-linux/vulgate_frida.so'),
        'operation_roots': ['ap_process_request_internal', 'ap_invoke_handler', 'ap_pass_brigade'],
        'lifecycle_hooks': lifecycle_hooks_for('httpd'),
        'builds': {
            'baseline': {
                'executable': str(artifact('httpd-2.4.68')),
                'source_dir': str(httpd_src),
                'module_search_root': str(httpd_src / 'modules'),
            },
            'reference': {
                'executable': str(artifact('httpd-2.4.71')),
                'source_dir': str(httpd_ref_b['source']),
                'module_search_root': str(Path(httpd_ref_b['source']) / 'modules'),
            },
        },
        'layout': layout('httpd-2.4.68'),
        'symbolic_slice': {
            'include_dirs': httpd_inc,
            'defines': ['_GNU_SOURCE'],
            'helper_includes': ['"httpd.h"', '"http_config.h"'],
        },
        'action_catalog': {
            'HTTPD_414_URI_TOO_LARGE': {'kind': 'return_int', 'value': 414},
            'HTTPD_503_UNAVAILABLE': {'kind': 'return_int', 'value': 503},
            'APR_EGENERAL_ERROR': {'kind': 'return_int', 'value': 20014},
            'HTTPD_VOID_SKIP': {'kind': 'return_void'},
            'HTTPD_EMPTY_STRING': {'kind': 'return_string', 'value': ''},
        },
    }
    paths['httpd-2.4.68'] = _write_yaml(profiles_dir / 'httpd-2.4.68.yaml', httpd_prof)

    php_folder = ROOT / 'build/postdeploy-php-session'
    php_b = json.loads((php_folder / 'build.json').read_text(encoding='utf-8'))
    php_src = Path(php_b['baseline']['source'])
    import subprocess as _sp
    _sp.run(['gcc', '-O0', '-I.', '-IZend', '-Imain', '-ITSRM',
             str(ROOT / 'experiments/postdeploy/benchmark20/layout_php.c'),
             '-o', str(php_src / 'vg_multipart_layout')], cwd=php_src, check=True)
    php_mp_lay = json.loads(_sp.check_output([php_src / 'vg_multipart_layout'], text=True))
    php_prof = {
        'schema': 'vulgate.app_profile/v2',
        'name': 'php-8.5.12-nts',
        'family': 'php',
        'protocol': 'php_http',
        'bridge': str(ROOT / 'build/frida-linux/vulgate_frida.so'),
        'router_script': str(ROOT / 'experiments/postdeploy/php_session/router.php'),
        'trace_anchor_symbol': 'php_session_rfc1867_callback',
        'operation_roots': ['php_request_startup', 'sapi_handle_post'],
        'lifecycle_hooks': lifecycle_hooks_for('php'),
        'builds': {
            'baseline': {
                'executable': str(php_folder / 'baseline/php'),
                'source_dir': str(php_src),
            },
            'reference': {
                'executable': str(php_folder / 'reference/php'),
                'source_dir': str(php_b['reference']['source']),
            },
        },
        'layout': {**php_b['baseline']['layout'], **php_mp_lay},
        'symbolic_slice': {
            'include_dirs': [str(php_src / sub) for sub in ('.', 'Zend', 'main', 'TSRM', 'ext')],
            'defines': [],
        },
        'action_catalog': {
            'PHP_MULTIPART_RETURN_VOID': {'kind': 'return_void'},
            'PHP_SESSION_SUCCESS': {'kind': 'return_int', 'value': 0},
        },
    }
    paths['php-8.5.12-nts'] = _write_yaml(profiles_dir / 'php-8.5.12-nts.yaml', php_prof)

    brotli_folder = ROOT / 'build/postdeploy-brotli'
    brotli_lay = json.loads((brotli_folder / 'layout.json').read_text(encoding='utf-8'))
    brotli_src = ROOT / 'build/postdeploy-sources/brotli/baseline'
    brotli_prof = {
        'schema': 'vulgate.app_profile/v2',
        'name': 'brotli-c-1.2.0',
        'family': 'brotli',
        'protocol': 'brotli_stream_rpc',
        'bridge': str(ROOT / 'build/frida-linux/vulgate_frida.so'),
        'encoder_binary': str(brotli_folder / 'encoder'),
        'operation_roots': ['BrotliDecoderDecompressStream'],
        'lifecycle_hooks': lifecycle_hooks_for('brotli'),
        'builds': {
            'baseline': {
                'executable': str(brotli_folder / 'baseline/worker'),
                'modules': {'libpd_brotli.so': str(brotli_folder / 'baseline/libpd_brotli.so')},
                'source_dir': str(brotli_src),
            },
            'reference': {
                'executable': str(brotli_folder / 'reference/worker'),
                'modules': {'libpd_brotli.so': str(brotli_folder / 'reference/libpd_brotli.so')},
                'source_dir': str(ROOT / 'build/postdeploy-sources/brotli/reference'),
            },
        },
        'layout': brotli_lay,
        'symbolic_slice': {
            'include_dirs': [str(brotli_src / 'c/include'), str(brotli_src / 'c/dec')],
            'defines': [],
            'helper_includes': ['<brotli/decode.h>', '"state.h"'],
        },
        'action_catalog': {
            'BROTLI_REFILL_FATAL': {'kind': 'return_int', 'value': int(brotli_lay['fatal'])},
        },
    }
    paths['brotli-c-1.2.0'] = _write_yaml(profiles_dir / 'brotli-c-1.2.0.yaml', brotli_prof)

    return paths


def generate_all_20_case_specs(spec_root: Path, profile_paths: dict[str, Path]) -> list[dict[str, Any]]:
    cases_dir = spec_root / 'cases'
    cases_dir.mkdir(parents=True, exist_ok=True)
    ngx_1316_src = Path(json.loads((BUILD / 'nginx-1.31.6/build.json').read_text(encoding='utf-8'))['source'])
    ngx_1310_src = Path(json.loads((BUILD / 'nginx-1.31.0/build.json').read_text(encoding='utf-8'))['source'])
    ngx_1296_src = Path(json.loads((BUILD / 'nginx-1.29.6/build.json').read_text(encoding='utf-8'))['source'])
    brotli_lay = json.loads((ROOT / 'build/postdeploy-brotli/layout.json').read_text(encoding='utf-8'))
    php_b = json.loads((ROOT / 'build/postdeploy-php-session/build.json').read_text(encoding='utf-8'))
    php_src = Path(php_b['baseline']['source'])
    import subprocess as _sp
    php_mp_lay = json.loads(_sp.check_output([php_src / 'vg_multipart_layout'], text=True))

    entries: list[tuple[str, str, dict[str, Any], dict[str, Any]]] = []

    entries.append((
        'CVE-2026-111497',
        'brotli-c-1.2.0',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-111497',
            'application': 'brotli-c-1.2.0',
            'defect_anchors': {
                'sink_site': {'file': 'c/dec/decode.c', 'function': 'WriteRingBuffer', 'role': 'memory_write'},
                'root_cause_site': {'file': 'c/dec/decode.c', 'function': 'DecodeBlockTypeAndLength'},
                'known_unhooked_entries': ['DecodeBlockTypeAndLength_direct_block_switch'],
                'state_carrier': {'expr': '*s', 'lifetime': 'call_tree'},
            },
            'safety_oracle': {'kind': 'physical_memory_safety', 'at': 'sink_site'},
            'environment_fixture': {'transient_maps': ['current_input']},
            'symbolization_scope': {
                'cut_harness_kind': 'brotli_stream_refill',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [
                    {'name': 'position'}, {'name': 'remaining'}, {'name': 'occupied'},
                    {'name': 'unread'}, {'name': 'available_in'}, {'name': 'output_capacity'},
                ],
                'field_to_input_map': {
                    'remaining': 'remaining', 'occupied': 'occupied',
                    'next_in': '0', 'last_in': 'unread',
                    'available_in': 'available_in', 'sample_present': '1',
                },
                'snapshot_to_symbolic_exprs': {
                    'unread': 'last_in - next_in',
                    'position': '0',
                    'output_capacity': '8',
                },
            },
            'budgets': {'loop_unwind': 32, 'max_impact_regions': 6, 'solver_timeout_sec': 120},
        },
        {
            'schema': 'vulgate.patch/v2',
            'maps': {'current_input': {'capacity': 64, 'thread_scoped': True}},
            'observers': [{
                'id': 'before_refill',
                'module': 'libpd_brotli.so',
                'map': 'current_input',
                'operation': 'set',
                'callsite': {
                    'caller': 'BrotliDecoderDecompressStream',
                    'callee': 'WriteRingBuffer',
                    'source_line': 2426,
                    'value_parameter': 'available_in',
                    'key_parameter': 's',
                    'deref_reads': [{'offset': 0, 'type': 'u64'}],
                },
            }],
            'guards': [{
                'id': 'refill_capacity',
                'module': 'libpd_brotli.so',
                'function': 'WriteRingBuffer',
                'return_from_observer': 'before_refill',
                'arg_types': ['pointer', 'pointer', 'pointer', 'pointer', 'int'],
                'parameter_names': ['s', 'available_out', 'next_out', 'total_out', 'force'],
                'return_type': 'int',
                'force_vm_arg_constant': True,
                'selectors': {
                    'remaining': {'arg': 0, 'reads': [{'offset': int(brotli_lay['remaining']), 'type': 's32'}], 'c_param_expr': '(uint64_t)(int64_t)((BrotliDecoderState *)s)->meta_block_remaining_len'},
                    'occupied': {'arg': 0, 'reads': [{'offset': int(brotli_lay['occupied']), 'type': 'u64'}], 'c_param_expr': '((BrotliDecoderState *)s)->buffer_length'},
                    'capacity': {'constant': int(brotli_lay['capacity']), 'c_param_expr': '8ULL'},
                    'next_in': {'arg': 0, 'reads': [{'offset': int(brotli_lay['next_in']), 'type': 'pointer'}], 'c_param_expr': '(uintptr_t)((BrotliDecoderState *)s)->br.next_in'},
                    'last_in': {'arg': 0, 'reads': [{'offset': int(brotli_lay['last_in']), 'type': 'pointer'}], 'c_param_expr': '(uintptr_t)((BrotliDecoderState *)s)->br.last_in'},
                },
                'map_reads': [{
                    'map': 'current_input',
                    'key_arg': 0,
                    'into': 'available_in',
                    'slot': 0,
                    'present_into': 'sample_present',
                    'present_slot': 1,
                    'consume': True,
                }],
                'expression': (
                    'remaining <= 2147483647 and (sample_present == 0 or occupied > capacity or '
                    'last_in < next_in or (occupied == 0 and last_in - next_in > capacity) or '
                    '(occupied > 0 and occupied == capacity and last_in > next_in and available_in > 0))'
                ),
                'action_id': 'BROTLI_REFILL_FATAL',
            }],
        },
    ))

    entries.append((
        'CVE-2026-93479',
        'nginx-1.31.6',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-93479',
            'application': 'nginx-1.31.6',
            'defect_anchors': {
                'sink_site': {'file': 'src/http/ngx_http_script.c', 'function': 'ngx_http_script_copy_code', 'role': 'memory_write'},
                'root_cause_site': {'file': 'src/http/ngx_http_script.c', 'function': 'ngx_http_script_run'},
                'known_unhooked_entries': ['ngx_stream_script_run'],
                'state_carrier': {'expr': '*e', 'lifetime': 'call_tree'},
            },
            'safety_oracle': {'kind': 'logical_region_bounds', 'at': 'sink_site'},
            'environment_fixture': {
                'config_template': _nginx_script_capture_conf(),
                'files': _nginx_std_files(),
            },
            'seed_traces': {
                'poc_reproducer': _script_capture_poc(),
                'benign_seeds': _nginx_base_seeds([
                    {'id': 'dynamic_root', 'group': 'dynamic_script_root', 'method': 'GET', 'path': '/dynamic/file.txt?dir=www', 'expected_status': 200},
                ]),
            },
            'symbolization_scope': {
                'slice_sources': [str(ngx_1316_src / 'src/http/ngx_http_script.c')],
                'cut_harness_kind': 'nginx_script_check_length',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'length'}],
                'field_to_input_map': {'length': 'length'},
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'ngx_http_script_check_length',
                'function': 'ngx_http_script_check_length',
                'arg_types': ['pointer', 'uint64'],
                'parameter_names': ['e', 'len'],
                'return_type': 'int64',
                'selectors': {'length': {'arg': 1, 'type': 'uint64'}},
                'expression': 'length != 0',
                'action_id': 'NGX_SCRIPT_EXIT_INT_ERROR',
            }],
        },
    ))

    entries.append((
        'CVE-2026-97205',
        'nginx-1.31.6',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-97205',
            'application': 'nginx-1.31.6',
            'defect_anchors': {
                'sink_site': {'file': 'src/http/ngx_http_copy_filter_module.c', 'function': 'ngx_http_copy_filter', 'role': 'refcount_update'},
                'known_unhooked_entries': ['ngx_http_file_cache_aio_read', 'ngx_http_upstream_process_request'],
                'state_carrier': {'expr': 'r->main->blocked', 'lifetime': 'request'},
            },
            'safety_oracle': {'kind': 'temporal_object_validity', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _nginx_conf_template(), 'files': _nginx_std_files()},
            'seed_traces': {'benign_seeds': _nginx_base_seeds()},
            'symbolization_scope': {
                'cut_harness_kind': 'nginx_copy_filter_aio',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'counter'}],
                'field_to_input_map': {'counter': 'counter'},
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'ngx_http_copy_filter',
                'function': 'ngx_http_copy_filter',
                'arg_types': ['pointer', 'pointer'],
                'parameter_names': ['r', 'in'],
                'return_type': 'int64',
                'selectors': {
                    'counter': {
                        'arg': 0,
                        'reads': [
                            {'struct_member': ['ngx_http_request_t', 'main'], 'type': 'pointer'},
                            {'struct_member': ['ngx_http_request_t', 'blocked'], 'type': 'u32'},
                        ],
                        'c_param_expr': '(((ngx_http_request_t *)r)->main->blocked * __BIT_UNIT_blocked__)',
                    },
                },
                'expression': '(counter & __BIT_MASK_blocked__) >= (250 * __BIT_UNIT_blocked__)',
                'action_id': 'NGX_ERROR_RETURN',
            }],
        },
    ))

    entries.append((
        'CVE-2026-15176',
        'nginx-1.31.6',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-15176',
            'application': 'nginx-1.31.6',
            'defect_anchors': {
                'sink_site': {'file': 'src/http/ngx_http_core_module.c', 'function': 'ngx_http_map_uri_to_path', 'role': 'memory_write'},
                'state_carrier': {'expr': '*r', 'lifetime': 'request'},
            },
            'safety_oracle': {'kind': 'physical_memory_safety', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _nginx_alias_rewrite_conf(), 'files': _nginx_std_files()},
            'seed_traces': {
                'poc_reproducer': _alias_rewrite_poc(),
                'benign_seeds': _nginx_base_seeds(),
            },
            'symbolization_scope': {
                'slice_sources': [str(ngx_1316_src / 'src/http/ngx_http_core_module.c')],
                'cut_harness_kind': 'nginx_alias_map_uri',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'alias'}, {'name': 'flags'}],
                'field_to_input_map': {'alias': 'alias', 'flags': '(flags * __BIT_UNIT_uri_changed__)'},
                'extra_predicates': ['alias != 0', 'flags != 0'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 6, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'ngx_http_map_uri_to_path',
                'function': 'ngx_http_map_uri_to_path',
                'arg_types': ['pointer', 'pointer', 'pointer', 'uint64'],
                'parameter_names': ['r', 'path', 'root_length', 'reserved'],
                'return_type': 'pointer',
                'selectors': {
                    'alias': {
                        'arg': 0,
                        'reads': [
                            {'struct_member': ['ngx_http_request_t', 'loc_conf'], 'type': 'pointer'},
                            {
                                'offset': 0,
                                'type': 'pointer',
                                'stride': 8,
                                'index': {
                                    'global_symbol': 'ngx_http_core_module',
                                    'reads': [{'struct_member': ['ngx_module_t', 'ctx_index'], 'type': 'u64'}],
                                },
                            },
                            {'struct_member': ['ngx_http_core_loc_conf_t', 'alias'], 'type': 'u64'},
                        ],
                        'c_param_expr': '((ngx_http_core_loc_conf_t *)ngx_http_get_module_loc_conf((ngx_http_request_t *)r, ngx_http_core_module))->alias',
                    },
                    'flags': {
                        'arg': 0,
                        'reads': [{'struct_member': ['ngx_http_request_t', 'uri_changed'], 'type': 'u32'}],
                        'c_param_expr': '(((ngx_http_request_t *)r)->uri_changed ? __BIT_MASK_uri_changed__ : 0ULL)',
                    },
                },
                'expression': 'alias != 0 and (flags & __BIT_MASK_uri_changed__) != 0',
                'action_id': 'NGX_NULL_RETURN',
            }],
        },
    ))

    entries.append((
        'CVE-2026-42533',
        'nginx-1.29.6',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-42533',
            'application': 'nginx-1.29.6',
            'defect_anchors': {
                'sink_site': {'file': 'src/http/modules/ngx_http_map_module.c', 'function': 'ngx_http_map_variable', 'role': 'state_mutation'},
                'known_unhooked_entries': ['ngx_http_complex_value_noncacheable', 'ngx_stream_map_variable'],
            },
            'safety_oracle': {'kind': 'state_invariant', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _nginx_conf_template(), 'files': _nginx_std_files()},
            'seed_traces': {'benign_seeds': _nginx_base_seeds([
                {'id': 'map', 'group': 'map_variable_eval', 'method': 'GET', 'path': '/map/ordinary', 'expected_status': 200},
            ])},
            'symbolization_scope': {
                'cut_harness_kind': 'nginx_map_variable',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'use_map'}],
                'extra_predicates': ['use_map == 1'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'ngx_http_map_variable',
                'function': 'ngx_http_map_variable',
                'arg_types': ['pointer', 'pointer', 'uint64'],
                'parameter_names': ['r', 'v', 'data'],
                'return_type': 'int64',
                'expression': 'True',
                'action_id': 'NGX_ERROR_RETURN',
            }],
        },
    ))

    entries.append((
        'CVE-2026-60005',
        'nginx-1.29.6',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-60005',
            'application': 'nginx-1.29.6',
            'defect_anchors': {
                'sink_site': {'file': 'src/http/ngx_http_variables.c', 'function': 'ngx_http_regex_exec', 'role': 'memory_read'},
                'known_unhooked_entries': ['ngx_http_regex_exec_null_captures_branch'],
            },
            'safety_oracle': {'kind': 'state_invariant', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _nginx_conf_template(), 'files': _nginx_std_files()},
            'seed_traces': {'benign_seeds': _nginx_base_seeds([
                {'id': 'regex', 'group': 'regex_map', 'method': 'GET', 'path': '/map/ordinary', 'expected_status': 200},
                {'id': 'slice', 'group': 'slice_range_proxy', 'method': 'GET', 'path': '/slice', 'expected_status': 200},
            ])},
            'symbolization_scope': {
                'slice_sources': [str(ngx_1296_src / 'src/http/ngx_http_variables.c')],
                'cut_harness_kind': 'nginx_regex_captures',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'captures'}, {'name': 'realloc'}],
                'extra_predicates': ['captures != 0', 'realloc != 0'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 6, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'ngx_http_regex_exec',
                'function': 'ngx_http_regex_exec',
                'arg_types': ['pointer', 'pointer', 'pointer'],
                'parameter_names': ['r', 're', 's'],
                'return_type': 'int64',
                'selectors': {
                    'captures': {
                        'arg': 0,
                        'reads': [{'struct_member': ['ngx_http_request_t', 'ncaptures'], 'type': 'u64'}],
                        'c_param_expr': '((ngx_http_request_t *)r)->ncaptures',
                    },
                    'flags': {
                        'arg': 0,
                        'reads': [{'struct_member': ['ngx_http_request_t', 'realloc_captures'], 'type': 'u32'}],
                        'c_param_expr': '(((ngx_http_request_t *)r)->realloc_captures ? __BIT_MASK_realloc_captures__ : 0ULL)',
                    },
                },
                'expression': 'captures != 0 and (flags & __BIT_MASK_realloc_captures__) != 0',
                'action_id': 'NGX_ERROR_RETURN',
            }],
        },
    ))

    for cve_id, ngx_ver, src_root in (
        ('CVE-2026-9256', 'nginx-1.31.0', ngx_1310_src),
        ('CVE-2026-42945', 'nginx-1.29.6', ngx_1296_src),
    ):
        entries.append((
            cve_id,
            ngx_ver,
            {
                'schema': 'vulgate.vuln/v2',
                'case_id': cve_id,
                'application': ngx_ver,
                'defect_anchors': {
                    'sink_site': {'file': 'src/http/ngx_http_script.c', 'function': 'ngx_http_script_regex_start_code', 'role': 'memory_write'},
                },
                'safety_oracle': {'kind': 'physical_memory_safety', 'at': 'sink_site'},
                'environment_fixture': {
                    'config_template': _nginx_isargs_conf() if cve_id == 'CVE-2026-42945' else _nginx_conf_template(),
                    'files': _nginx_std_files(),
                },
                'seed_traces': {
                    **({'poc_reproducer': _isargs_poc()} if cve_id == 'CVE-2026-42945' else {}),
                    'benign_seeds': _nginx_base_seeds([
                        {'id': 'rewrite', 'group': 'regex_rewrite', 'method': 'GET', 'path': '/rewrite/ordinary', 'expected_status': 302},
                    ]),
                },
                'symbolization_scope': {
                    'slice_sources': [str(src_root / 'src/http/ngx_http_script.c')],
                    'cut_harness_kind': 'nginx_script_regex_start',
                    'enable_uninitialized_shadow': True,
                    'symbolic_inputs': [{'name': 'invoke_regex'}],
                    'extra_predicates': ['invoke_regex == 1'],
                },
                'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
            },
            {
                'schema': 'vulgate.patch/v2',
                'guards': [{
                    'id': 'ngx_http_script_regex_start_code',
                    'function': 'ngx_http_script_regex_start_code',
                    'arg_types': ['pointer'],
                    'parameter_names': ['e'],
                    'return_type': 'void',
                    'expression': 'True',
                    'action_id': 'NGX_SCRIPT_EXIT_VOID_ERROR',
                }],
            },
        ))

    entries.append((
        'CVE-2026-42055',
        'nginx-1.29.6',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-42055',
            'application': 'nginx-1.29.6',
            'defect_anchors': {
                'sink_site': {'file': 'src/http/modules/ngx_http_proxy_v2_module.c', 'function': 'ngx_http_proxy_v2_create_request', 'role': 'memory_write'},
            },
            'safety_oracle': {'kind': 'physical_memory_safety', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _nginx_conf_template(), 'files': _nginx_std_files()},
            'seed_traces': {'benign_seeds': _nginx_base_seeds([
                {'id': 'proxy_http2', 'group': 'h2_upstream_proxy', 'method': 'GET', 'path': '/h2proxy', 'expected_status': 200},
                {'id': 'grpc', 'group': 'grpc_upstream', 'method': 'GET', 'path': '/grpc', 'expected_status': 200},
            ])},
            'symbolization_scope': {
                'cut_harness_kind': 'nginx_h2_grpc_serializers',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'proto_mode'}],
                'extra_predicates': ['proto_mode == 0', 'proto_mode == 1'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 6, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [
                {
                    'id': 'ngx_http_proxy_v2_create_request',
                    'function': 'ngx_http_proxy_v2_create_request',
                    'arg_types': ['pointer'],
                    'parameter_names': ['r'],
                    'return_type': 'int64',
                    'expression': 'True',
                    'action_id': 'NGX_ERROR_RETURN',
                },
                {
                    'id': 'ngx_http_grpc_create_request',
                    'function': 'ngx_http_grpc_create_request',
                    'arg_types': ['pointer'],
                    'parameter_names': ['r'],
                    'return_type': 'int64',
                    'expression': 'True',
                    'action_id': 'NGX_ERROR_RETURN',
                },
            ],
        },
    ))

    entries.append((
        'CVE-2026-27654',
        'nginx-1.29.6',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-27654',
            'application': 'nginx-1.29.6',
            'defect_anchors': {
                'sink_site': {'file': 'src/http/modules/ngx_http_dav_module.c', 'function': 'ngx_http_dav_copy_move_handler', 'role': 'memory_write'},
            },
            'safety_oracle': {'kind': 'physical_memory_safety', 'at': 'sink_site'},
            'environment_fixture': {
                'config_template': _nginx_dav_alias_conf(),
                'files': {
                    **_nginx_std_files(),
                    'www/really-long-directory-name/poc-src.txt': 'ordinary DAV file\n',
                },
            },
            'seed_traces': {
                'poc_reproducer': _dav_short_destination_poc(),
                'benign_seeds': _nginx_base_seeds([
                    {'id': 'copy', 'group': 'dav_copy_move', 'method': 'COPY', 'path': '/dav/source.txt', 'headers': {'Destination': '/dav/copy.txt'}, 'expected_status': 204},
                ]),
            },
            'symbolization_scope': {
                'cut_harness_kind': 'nginx_dav_copy_move',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'method'}],
                'extra_predicates': ['method == 2'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'ngx_http_dav_copy_move_handler',
                'function': 'ngx_http_dav_copy_move_handler',
                'arg_types': ['pointer'],
                'parameter_names': ['r'],
                'return_type': 'int64',
                'expression': 'True',
                'action_id': 'NGX_HTTP_405_RETURN',
            }],
        },
    ))

    entries.append((
        'CVE-2026-63292',
        'httpd-2.4.68',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-63292',
            'application': 'httpd-2.4.68',
            'defect_anchors': {
                'sink_site': {'file': 'modules/mappers/mod_vhost_alias.c', 'function': 'vhost_alias_interpolate', 'role': 'memory_write'},
            },
            'safety_oracle': {'kind': 'physical_memory_safety', 'at': 'sink_site'},
            'environment_fixture': {
                'config_template': _httpd_conf_template('VirtualDocumentRoot {root}/www\n'),
                'files': _httpd_std_files(),
            },
            'seed_traces': {'benign_seeds': _httpd_base_seeds()},
            'symbolization_scope': {
                'cut_harness_kind': 'httpd_vhost_translate',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'is_slash'}],
                'extra_predicates': ['is_slash == 1'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'mva_translate',
                'module': 'mod_vhost_alias.so',
                'function': 'mva_translate',
                'arg_types': ['pointer'],
                'parameter_names': ['r'],
                'return_type': 'int',
                'expression': 'True',
                'action_id': 'HTTPD_414_URI_TOO_LARGE',
            }],
        },
    ))

    entries.append((
        'CVE-2026-57941',
        'httpd-2.4.68',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-57941',
            'application': 'httpd-2.4.68',
            'defect_anchors': {
                'sink_site': {'file': 'modules/http2/h2_session.c', 'function': 'h2_c1_setup', 'role': 'reentrancy_state'},
                'state_carrier': {'expr': '*c', 'lifetime': 'connection'},
            },
            'safety_oracle': {'kind': 'state_invariant', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _httpd_conf_template(), 'files': _httpd_std_files()},
            'seed_traces': {'benign_seeds': _httpd_base_seeds([
                {'id': 'http2', 'group': 'http2_direct', 'method': 'GET', 'path': '/plain.txt', 'protocol': 'h2', 'expected_status': 200},
            ])},
            'symbolization_scope': {
                'cut_harness_kind': 'httpd_h2_c1_setup',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'is_h2'}],
                'extra_predicates': ['is_h2 == 1'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'h2_c1_setup',
                'module': 'mod_http2.so',
                'function': 'h2_c1_setup',
                'arg_types': ['pointer', 'pointer', 'pointer'],
                'parameter_names': ['c', 'r', 's'],
                'return_type': 'int',
                'expression': 'True',
                'action_id': 'APR_EGENERAL_ERROR',
            }],
        },
    ))

    entries.append((
        'CVE-2026-93546',
        'httpd-2.4.68',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-93546',
            'application': 'httpd-2.4.68',
            'defect_anchors': {
                'sink_site': {'file': 'modules/dav/main/mod_dav.c', 'function': 'dav_method_proppatch', 'role': 'state_mutation'},
            },
            'safety_oracle': {'kind': 'state_invariant', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _httpd_conf_template(), 'files': _httpd_std_files()},
            'seed_traces': {'benign_seeds': _httpd_base_seeds([
                {
                    'id': 'proppatch',
                    'group': 'webdav_proppatch',
                    'method': 'PROPPATCH',
                    'path': '/dav/file.txt',
                    'headers': {'Content-Type': 'application/xml'},
                    'body': '<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:X="urn:ordinary"><D:set><D:prop><X:label>hello</X:label></D:prop></D:set></D:propertyupdate>',
                    'expected_status': 207,
                },
            ])},
            'symbolization_scope': {
                'cut_harness_kind': 'httpd_dav_proppatch',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'method'}],
                'extra_predicates': ['method == 0'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'dav_method_proppatch',
                'module': 'mod_dav.so',
                'function': 'dav_method_proppatch',
                'arg_types': ['pointer'],
                'parameter_names': ['r'],
                'return_type': 'int',
                'expression': 'True',
                'action_id': 'HTTPD_503_UNAVAILABLE',
            }],
        },
    ))

    entries.append((
        'CVE-2026-47360',
        'httpd-2.4.68',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-47360',
            'application': 'httpd-2.4.68',
            'defect_anchors': {
                'sink_site': {'file': 'modules/proxy/mod_proxy.c', 'function': 'proxy_handler', 'role': 'header_forwarding'},
                'known_unhooked_entries': ['non_proxy_internal_redirect_handlers'],
            },
            'safety_oracle': {'kind': 'state_invariant', 'at': 'sink_site'},
            'environment_fixture': {
                'config_template': _httpd_conf_template('ErrorDocument 404 /proxy/plain\n'),
                'files': _httpd_std_files(),
            },
            'seed_traces': {'benign_seeds': _httpd_base_seeds([
                {'id': 'redirect', 'group': 'internal_redirect_proxy', 'method': 'GET', 'path': '/missing-internal-redirect', 'expected_status': 200},
            ])},
            'symbolization_scope': {
                'cut_harness_kind': 'httpd_session_proxy',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'previous'}],
                'field_to_input_map': {'previous': 'previous'},
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'proxy_handler',
                'module': 'mod_proxy.so',
                'function': 'proxy_handler',
                'arg_types': ['pointer'],
                'parameter_names': ['r'],
                'return_type': 'int',
                'selectors': {
                    'previous': {
                        'arg': 0,
                        'reads': [{'struct_member': ['request_rec', 'prev'], 'type': 'pointer'}],
                        'c_param_expr': '(uintptr_t)(((request_rec *)r)->prev)',
                    },
                },
                'expression': 'previous != 0',
                'action_id': 'HTTPD_503_UNAVAILABLE',
            }],
        },
    ))

    entries.append((
        'CVE-2026-63686',
        'httpd-2.4.68',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-63686',
            'application': 'httpd-2.4.68',
            'defect_anchors': {
                'sink_site': {'file': 'modules/filters/mod_xml2enc.c', 'function': 'xml2enc_ffunc', 'role': 'memory_write'},
            },
            'safety_oracle': {'kind': 'physical_memory_safety', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _httpd_conf_template(), 'files': _httpd_std_files()},
            'seed_traces': {'benign_seeds': _httpd_base_seeds([
                {'id': 'html', 'group': 'xml2enc_html_filter', 'method': 'GET', 'path': '/html', 'expected_status': 200},
            ])},
            'symbolization_scope': {
                'cut_harness_kind': 'httpd_xml2enc_filter',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'filter_en'}],
                'extra_predicates': ['filter_en == 1'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'xml2enc_ffunc',
                'module': 'mod_xml2enc.so',
                'function': 'xml2enc_ffunc',
                'arg_types': ['pointer', 'pointer'],
                'parameter_names': ['f', 'bb'],
                'return_type': 'int',
                'expression': 'True',
                'action_id': 'APR_EGENERAL_ERROR',
            }],
        },
    ))

    entries.append((
        'CVE-2026-56153',
        'httpd-2.4.68',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-56153',
            'application': 'httpd-2.4.68',
            'defect_anchors': {
                'sink_site': {'file': 'modules/filters/mod_charset_lite.c', 'function': 'finish_partial_char_sink', 'role': 'memory_write'},
                'known_unhooked_entries': ['xlate_in_filter'],
            },
            'safety_oracle': {'kind': 'physical_memory_safety', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _httpd_conf_template(), 'files': _httpd_std_files()},
            'seed_traces': {'benign_seeds': _httpd_base_seeds([
                {'id': 'latin', 'group': 'charset_lite_output', 'method': 'GET', 'path': '/latin.txt', 'expected_status': 200},
            ])},
            'symbolization_scope': {
                'cut_harness_kind': 'httpd_charset_out_filter',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'filter_en'}],
                'extra_predicates': ['filter_en == 1'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'xlate_out_filter',
                'module': 'mod_charset_lite.so',
                'function': 'xlate_out_filter',
                'arg_types': ['pointer', 'pointer'],
                'parameter_names': ['f', 'bb'],
                'return_type': 'int',
                'expression': 'True',
                'action_id': 'APR_EGENERAL_ERROR',
            }],
        },
    ))

    entries.append((
        'CVE-2026-56449',
        'httpd-2.4.68',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-56449',
            'application': 'httpd-2.4.68',
            'defect_anchors': {
                'sink_site': {'file': 'modules/filters/mod_proxy_html.c', 'function': 'pcomment', 'role': 'premature_flush'},
            },
            'safety_oracle': {'kind': 'temporal_object_validity', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _httpd_conf_template(), 'files': _httpd_std_files()},
            'seed_traces': {'benign_seeds': _httpd_base_seeds([
                {'id': 'html', 'group': 'proxy_html_comment', 'method': 'GET', 'path': '/html', 'expected_status': 200},
            ])},
            'symbolization_scope': {
                'cut_harness_kind': 'httpd_proxy_html_comment',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'has_comment'}],
                'extra_predicates': ['has_comment == 1'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'pcomment',
                'module': 'mod_proxy_html.so',
                'function': 'pcomment',
                'arg_types': ['pointer', 'pointer'],
                'parameter_names': ['ctxt', 'uchars'],
                'return_type': 'void',
                'expression': 'True',
                'action_id': 'HTTPD_VOID_SKIP',
            }],
        },
    ))

    entries.append((
        'CVE-2026-56154',
        'httpd-2.4.68',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-56154',
            'application': 'httpd-2.4.68',
            'defect_anchors': {
                'sink_site': {'file': 'modules/mappers/mod_rewrite.c', 'function': 'lookup_variable', 'role': 'use_after_free'},
            },
            'safety_oracle': {'kind': 'temporal_object_validity', 'at': 'sink_site'},
            'environment_fixture': {'config_template': _httpd_conf_template(), 'files': _httpd_std_files()},
            'seed_traces': {'benign_seeds': _httpd_base_seeds([
                {'id': 'condition', 'group': 'rewrite_cond_var', 'method': 'GET', 'path': '/condition', 'headers': {'User-Agent': 'ordinary'}, 'expected_status': 200},
            ])},
            'symbolization_scope': {
                'cut_harness_kind': 'httpd_rewrite_lookup',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'uses_var'}],
                'extra_predicates': ['uses_var == 1'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'lookup_variable',
                'module': 'mod_rewrite.so',
                'function': 'lookup_variable',
                'arg_types': ['pointer', 'pointer'],
                'parameter_names': ['var', 'ctx'],
                'return_type': 'pointer',
                'expression': 'True',
                'action_id': 'HTTPD_EMPTY_STRING',
            }],
        },
    ))

    entries.append((
        'CVE-2026-109618',
        'php-8.5.12-nts',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-109618',
            'application': 'php-8.5.12-nts',
            'defect_anchors': {
                'sink_site': {'file': 'main/rfc1867.c', 'function': 'rfc1867_post_handler', 'role': 'oom_partial_init'},
                'known_unhooked_entries': ['zend_alloc_non_multipart_oom_paths'],
                'state_carrier': {'expr': 'SG(rfc1867_uploaded_files)', 'lifetime': 'request'},
            },
            'safety_oracle': {'kind': 'initialized_read_safety', 'at': 'sink_site'},
            'environment_fixture': {
                'admission_checks': [
                    {'name': 'original callback chain empty', 'symbol': 'php_session_rfc1867_orig_callback', 'expected_symbol': None},
                    {'name': 'registered callback is session callback', 'symbol': 'php_rfc1867_callback', 'expected_symbol': 'php_session_rfc1867_callback'},
                    {'name': 'no preexisting progress state', 'symbol': 'ps_globals', 'add_offset': int(php_b['baseline']['layout']['progress_offset']), 'expected_symbol': None},
                ],
            },
            'symbolization_scope': {
                'cut_harness_kind': 'php_multipart_startup',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'is_mp'}, {'name': 'activated'}],
                'field_to_input_map': {'activated': 'activated', 'throws': '0', 'uploads': '0'},
                'extra_predicates': ['is_mp == 1', 'activated == 0'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 6, 'solver_timeout_sec': 90},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'multipart_startup',
                'module': 'php',
                'function': 'rfc1867_post_handler',
                'arg_types': ['pointer', 'pointer'],
                'parameter_names': ['content_type_dup', 'arg'],
                'return_type': 'void',
                'selectors': {
                    'activated': {
                        'global_symbol': 'core_globals',
                        'reads': [{'offset': int(php_mp_lay['modules_activated']), 'type': 'u8'}],
                        'symbolic_var_decl': 'extern uint8_t __vg_php_sym_activated;',
                        'symbolic_var_expr': '__vg_php_sym_activated',
                    },
                    'throws': {
                        'global_symbol': 'sapi_globals',
                        'reads': [{'offset': int(php_mp_lay['throws']), 'type': 'u8'}],
                        'symbolic_var_decl': 'extern uint8_t __vg_php_sym_throws;',
                        'symbolic_var_expr': '__vg_php_sym_throws',
                    },
                    'uploads': {
                        'global_symbol': 'sapi_globals',
                        'reads': [{'offset': int(php_mp_lay['uploads']), 'type': 'pointer'}],
                        'symbolic_var_decl': 'extern uintptr_t __vg_php_sym_uploads;',
                        'symbolic_var_expr': '__vg_php_sym_uploads',
                    },
                },
                'expression': 'activated == 0 and throws == 0 and uploads == 0',
                'action_id': 'PHP_MULTIPART_RETURN_VOID',
            }],
        },
    ))

    entries.append((
        'CVE-2026-109619',
        'php-8.5.12-nts',
        {
            'schema': 'vulgate.vuln/v2',
            'case_id': 'CVE-2026-109619',
            'application': 'php-8.5.12-nts',
            'defect_anchors': {
                'sink_site': {'file': 'ext/session/session.c', 'function': 'php_session_rfc1867_callback', 'role': 'stale_worker_global'},
                'known_unhooked_entries': ['php_request_shutdown_non_session_globals'],
                'state_carrier': {'expr': 'PS(rfc1867_progress)', 'lifetime': 'worker'},
            },
            'safety_oracle': {'kind': 'temporal_object_validity', 'at': 'sink_site'},
            'environment_fixture': {
                'admission_checks': [
                    {'name': 'original callback chain empty', 'symbol': 'php_session_rfc1867_orig_callback', 'expected_symbol': None},
                    {'name': 'registered callback is session callback', 'symbol': 'php_rfc1867_callback', 'expected_symbol': 'php_session_rfc1867_callback'},
                    {'name': 'no preexisting progress state', 'symbol': 'ps_globals', 'add_offset': int(php_b['baseline']['layout']['progress_offset']), 'expected_symbol': None},
                ],
            },
            'symbolization_scope': {
                'cut_harness_kind': 'php_session_progress',
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'has_prog'}],
                'extra_predicates': ['has_prog == 1'],
            },
            'budgets': {'loop_unwind': 16, 'max_impact_regions': 4, 'solver_timeout_sec': 90, 'episode_length': 2},
        },
        {
            'schema': 'vulgate.patch/v2',
            'guards': [{
                'id': 'session_progress_off',
                'module': 'php',
                'function': 'php_session_rfc1867_callback',
                'arg_types': ['uint', 'pointer', 'pointer'],
                'parameter_names': ['event', 'event_data', 'extra'],
                'return_type': 'int',
                'expression': 'True',
                'action_id': 'PHP_SESSION_SUCCESS',
            }],
        },
    ))

    manifest_rows = []
    for cve_id, app_key, v_spec, p_spec in entries:
        extra = CASE_ORACLE_BINDINGS.get(cve_id)
        if extra:
            oracle = v_spec.setdefault('safety_oracle', {})
            bindings = dict(oracle.get('bindings') or {})
            bindings.update(extra)
            oracle['bindings'] = bindings
        cdir = cases_dir / cve_id
        v_path = _write_yaml(cdir / 'vuln.yaml', v_spec)
        p_path = _write_yaml(cdir / 'patch.yaml', p_spec)
        manifest_rows.append({
            'case_id': cve_id,
            'app_key': app_key,
            'app_profile': str(profile_paths[app_key]),
            'vuln_spec': str(v_path),
            'patch_spec': str(p_path),
        })
    (spec_root / 'index.json').write_text(json.dumps(manifest_rows, indent=2) + '\n', encoding='utf-8')
    return manifest_rows


def run_batch(spec_root: Path, results_root: Path, selected_cases: list[str] | None = None, cbmc: Path | None = None) -> dict[str, Any]:
    spec_root = spec_root.resolve()
    results_root = results_root.resolve()
    results_root.mkdir(parents=True, exist_ok=True)
    profiles = generate_app_profiles(spec_root)
    rows = generate_all_20_case_specs(spec_root, profiles)

    if selected_cases:
        wanted = set(selected_cases)
        rows = [r for r in rows if r['case_id'] in wanted]

    summary_rows = []
    started = time.monotonic()
    for row in rows:
        cid = row['case_id']
        print(f'[evaluate] starting {cid} ({row["app_key"]}) ...', flush=True)
        try:
            rep = evaluate_case(
                Path(row['vuln_spec']),
                Path(row['patch_spec']),
                Path(row['app_profile']),
                results_root / cid,
                cbmc_bin=cbmc,
            )
            cs = rep['correctness_and_safety']
            pf = rep['path_and_functional_metrics']
            fix = pf['functional_impact_fixed_eval']
            reg = pf['symbolic_impact_regions']
            cov = pf['paired_coverage']
            summary_rows.append({
                'case_id': cid,
                'application': rep['application'],
                'installation': rep['installation']['status'],
                'vm_equivalence': cs['vm_bytecode_equivalence']['status'],
                'action_and_caller_continuation': cs['action_and_caller_continuation']['status'],
                'cut_functions': cs['action_and_caller_continuation'].get('scope', {}).get('cut_functions', []),
                'target_elimination': cs['target_vulnerability_elimination']['status'],
                'cut_local_target': cs['target_vulnerability_elimination'].get('cut_local_status'),
                'bypass_paths': cs['target_vulnerability_elimination'].get('bypass_paths', []),
                'impact_regions_total': reg['total_regions'],
                'unchanged_regions': reg['unchanged_regions'],
                'changed_by_block_regions': reg['changed_by_block_regions'],
                'fixed_eval_changed': f"{fix['changed_cases']}/{fix['denominator_valid_benign_cases']}",
                'fixed_eval_changed_fraction': round(fix['changed_fraction'], 4),
                'vm_decisions': pf['hook_triggering']['decisions'],
                'vm_blocks': pf['hook_triggering']['block_decisions'],
                'replay_violations': pf['hook_triggering']['replay_violations'],
                'retained_edge_fraction': cov['retained_edge_fraction'],
                'lost_edges': cov['lost_edge_union'],
                'elapsed_seconds': round(rep['elapsed_seconds'], 2),
            })
            print(json.dumps(summary_rows[-1], ensure_ascii=False), flush=True)
        except Exception as exc:
            traceback.print_exc()
            summary_rows.append({
                'case_id': cid,
                'status': 'ERROR',
                'error': str(exc),
            })
        (results_root / 'batch-summary.json').write_text(
            json.dumps({'cases': summary_rows, 'total_elapsed_seconds': round(time.monotonic() - started, 2)}, indent=2, ensure_ascii=False) + '\n',
            encoding='utf-8',
        )

    return {'cases': summary_rows, 'total_elapsed_seconds': time.monotonic() - started}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--specs-out', type=Path, default=ROOT / 'build/declarative20-specs')
    parser.add_argument('--results-out', type=Path, required=True)
    parser.add_argument('--cases', nargs='*', default=None)
    parser.add_argument('--cbmc', type=Path, default=None)
    args = parser.parse_args()
    run_batch(args.specs_out, args.results_out, args.cases, args.cbmc)

