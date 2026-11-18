"""Build-specific typed offsets and unique ELF symbol identities."""
import json
from pathlib import Path
import subprocess
from elftools.elf.elffile import ELFFile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BUILD=ROOT/'build/benchmark20'


def symbols(path):
    with path.open('rb') as file:
        elf=ELFFile(file)
        base=min(p['p_vaddr'] for p in elf.iter_segments() if p['p_type']=='PT_LOAD')
    result={}
    for line in subprocess.check_output(['nm','-an','--defined-only',str(path)],text=True).splitlines():
        row=line.split()
        if len(row)!=3: continue
        result.setdefault(row[2],[]).append(int(row[0],16)-base)
    return {name:values[0] for name,values in result.items() if len(values)==1}


def layout(name):
    folder=BUILD/name
    result=folder/'layout.json'
    if result.exists() and result.stat().st_mtime >= max((HERE/'layout_nginx.c').stat().st_mtime,
                                                        (HERE/'layout_httpd.c').stat().st_mtime):
        return json.loads(result.read_text())
    source=Path(json.loads((folder/'build.json').read_text())['source'])
    if name.startswith('nginx'):
        includes=['src/core','src/event','src/event/modules','src/os/unix','src/http',
                  'src/http/modules','src/http/v2','src/stream','objs']
        cmd=['gcc','-O0']+['-I'+str(source/p) for p in includes]+[str(HERE/'layout_nginx.c')]
    else:
        cmd=['gcc','-O0','-I'+str(source/'include'),'-I'+str(source/'os/unix'),
             '-I/usr/include/apr-1.0',str(HERE/'layout_httpd.c')]
    executable=source/'vg_layout'
    subprocess.run(cmd+['-o',str(executable)],check=True)
    obj=json.loads(subprocess.check_output([executable],text=True))
    result.write_text(json.dumps(obj,indent=2)+'\n')
    return obj


def artifact(name,module=None):
    folder=BUILD/name
    if module:
        source=Path(json.loads((folder/'build.json').read_text())['source'])
        candidates=list((source/'modules').rglob(module))
        if len(candidates)!=1: raise ValueError('module not unique: '+str(candidates))
        return candidates[0]
    return folder/('nginx' if name.startswith('nginx') else 'httpd')
