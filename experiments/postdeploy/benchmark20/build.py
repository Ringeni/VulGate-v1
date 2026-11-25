"""Build pinned, symbol-preserving HTTP servers for benign regression experiments."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OUTPUT = ROOT / 'build/benchmark20'
SCRATCH = Path('/tmp/vulgate-benchmark20-20261112')
TARGETS = ['nginx-1.29.6', 'nginx-1.31.0', 'nginx-1.31.6', 'nginx-1.31.7', 'httpd-2.4.68', 'httpd-2.4.71']
INSTRUMENT = ['ngx_http_script.c', 'ngx_http_core_module.c', 'ngx_http_dav_module.c',
    'ngx_http_slice_filter_module.c', 'ngx_http_rewrite_module.c', 'ngx_http_grpc_module.c',
    'ngx_http_proxy_v2_module.c', 'ngx_http_copy_filter_module.c', 'ngx_http_file_cache.c',
    'mod_vhost_alias.c', 'mod_session_cookie.c', 'mod_auth_digest.c', 'mod_rewrite.c',
    'mod_charset_lite.c', 'mod_proxy_html.c', 'mod_dav.c', 'dbm.c', 'h2_session.c']


def build(name):
    output, source = OUTPUT / name, SCRATCH / name
    output.mkdir(parents=True, exist_ok=True)
    trace_hash = hashlib.sha256((HERE / 'trace.c').read_bytes()).hexdigest()
    previous = json.loads((output / 'build.json').read_text()) if (output / 'build.json').exists() else {}
    if (previous.get('trace_runtime_sha256') == trace_hash
            and Path(previous.get('executable', '/nonexistent')).is_file()
            and (source / 'configure').is_file()):
        print(name + ': already built', flush=True)
        return
    archive = OUTPUT / (name + '.tar.gz')
    if not (source / 'configure').exists():
        with tarfile.open(archive) as bundle:
            for member in bundle:
                relative = Path(*Path(member.name).parts[1:])
                if relative.is_absolute() or '..' in relative.parts: raise ValueError('archive path')
                if not member.isfile(): continue
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(bundle.extractfile(member).read())
                path.chmod(member.mode & 0o777)
    commands = []
    def run(args, label, env=None):
        print(name + ': ' + label, flush=True)
        commands.append(list(map(str, args)))
        with (output / (label + '.log')).open('w') as log:
            subprocess.run(list(map(str, args)), cwd=source, env=env, stdout=log, stderr=log, check=True)
    trace, io = source / 'vg_trace.o', source / 'vg_io.o'
    run(['gcc', '-O1', '-g', '-fPIC', '-I' + str(ROOT / 'runtime/experiment'), '-c',
         HERE / 'trace.c', '-o', trace], 'trace')
    run(['gcc', '-O1', '-g', '-fPIC', '-I' + str(ROOT / 'runtime/experiment'), '-c',
         HERE.parent / 'php_session/trace_io.c', '-o', io], 'trace-io')
    compiler = source / 'vg_cc.py'
    compiler.write_text('#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\n'
        'a=sys.argv[1:]\nfiles=' + repr(INSTRUMENT) + '\n'
        'if "-c" in a and any(Path(x).name in files for x in a): a += ["-fsanitize-coverage=trace-pc"]\n'
        'os.execv("/usr/bin/gcc", ["gcc"]+a)\n')
    compiler.chmod(0o755)
    flags = '-O0 -g -fno-omit-frame-pointer'
    libs = f'{trace} {io} -ldl -lpthread'
    env = dict(os.environ, CC=str(compiler), CFLAGS=flags)
    if name.startswith('nginx'):
        command = ['./configure', '--prefix=' + str(output / 'install'), '--with-cc=' + str(compiler),
            '--with-cc-opt=' + flags, '--with-ld-opt=-Wl,--export-dynamic ' + libs,
            '--with-debug', '--with-threads', '--with-file-aio', '--with-http_ssl_module',
            '--with-http_v2_module', '--with-http_dav_module', '--with-http_slice_module',
            '--with-stream', '--with-stream_ssl_module']
        binary = source / 'objs/nginx'
    else:
        env.update(LDFLAGS='-Wl,--export-dynamic', LIBS=libs)
        modules = 'access_compat alias auth_basic auth_digest authn_core authn_file authz_core authz_host authz_user dir mime log_config unixd vhost_alias rewrite session session_cookie dav dav_fs charset_lite filter proxy proxy_http proxy_html xml2enc http2 ssl'
        command = ['./configure', '--prefix=' + str(output / 'install'), '--with-mpm=event',
            '--enable-modules=' + modules, '--enable-mods-shared=none', '--disable-lua',
            '--disable-cgi', '--disable-cgid', '--with-apr=/usr/bin/apr-1-config',
            '--with-apr-util=/usr/bin/apu-1-config', '--with-libxml2=/usr']
        binary = source / 'httpd'
    if not (source / 'Makefile').exists(): run(command, 'configure', env)
    if previous and binary.exists(): binary.unlink()  # Only this generated build artifact.
    run(['make', '-j1' if name.startswith('httpd') else '-j4'], 'make', env)
    executable = output / ('nginx' if name.startswith('nginx') else 'httpd')
    shutil.copy2(binary, executable)
    result = {'name': name, 'source': str(source), 'executable': str(executable), 'trace_runtime_sha256': trace_hash,
        'source_receipt': json.loads((OUTPUT / (name + '.source.json')).read_text()),
        'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
        'commands': commands, 'instrumented_files': INSTRUMENT,
        'environment': {k: env.get(k) for k in ['CC', 'CFLAGS', 'LDFLAGS', 'LIBS']}}
    (output / 'build.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('targets', nargs='*', default=TARGETS)
    args = parser.parse_args()
    for target in args.targets: build(target)
