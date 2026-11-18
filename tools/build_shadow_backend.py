"""Build the pinned aggregate-pointer shadow correction in a private prefix.

Use native Linux with GCC, G++, CMake, Make, Flex, Bison and patch installed.
The existing official toolchain is retained. Every build applies the JSON control
escaping and streaming typed transport corrections and rebuilds all four tools;
reports fingerprint each executable. Whole-model import qualification is separate.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

from tools.verification.toolchain import Toolchain


SOURCE_SHA256 = '217e5ed631bbd4b39659fde37a603482003605abd4cb2586b09c2da344d925db'
SOLVER_SHA256 = 'e54afa3c192c1753bc8075c0c7e126d5c495d9066e3f90a2588091149ac9ca40'
PATCH = Path(__file__).with_name('backend_patches') / 'cbmc-6.11.0-shadow-pointer-aggregates.patch'
PATCH_SHA256 = '60b420fd07bcdb5683046e53098f089899a999e16300ffd8a393082e5d2f3f0d'
ORIGINAL_FILE_SHA256 = '3365b61f23ae19031a220fb70046d976b3c5ae06a807b99cc30cd78e01733d70'
PATCHED_FILE_SHA256 = '355e6e850bc4f56020dc6cf2c25a744b148264bde5e896acdba809579a5f9992'
JSON_PATCH = PATCH.with_name('cbmc-6.11.0-json-control-escaping.patch')
JSON_PATCH_SHA256 = 'cab707ed3b8cc65d7bf550373d873ff00f92b13441caa51b3bf7d760fbf2a52a'
JSON_ORIGINAL_SHA256 = 'f60e670b2a46f6a88cc7b4bea8a555c20d9724985f8b22b1bec34af4b816c62b'
JSON_PATCHED_SHA256 = '13391babc6d80d2e5eb9885177ce7380deb2e376c50d3fdc3e066dce599ecd35'
TYPED_EXPORT_PATCH = PATCH.with_name('cbmc-6.11.0-full-typed-export.patch')
TYPED_EXPORT_PATCH_SHA256 = 'a71a552d6f5e26af859b766e8e4134ce7a717729d6c58607bba4a6eb7511ad33'
TYPED_EXPORT_FILES = (
    ('src/goto-programs/show_goto_functions_json.cpp',
     'fc4db337ef8439f8026e6e241f3228272541d8b53dd306a68e164faaac0f1e06',
     'f33cf4fcc43705ba09f993c5d7a06818e143274ce2e212c2df1baa8cbc2ebf96'),
    ('src/goto-programs/show_goto_functions_json.h',
     'f9f821a84b20aaaad30d0ace804a3a16cbfe5c92baa8678015ec8c369668a608',
     '067938c30664aa430fcee3735d45584b17dbce41d3c7b532ae5f382091c23f94'),
    ('src/goto-programs/show_goto_functions.cpp',
     '5815194c0c55b6a7bd07b0a726f592201ecd4931cd39660f1dad680a97114727',
     '778dc586d4a8a7abc67b2fda2a98880183c97652e08e9e5362f73a00bb237f94'),
    ('src/goto-programs/show_symbol_table.cpp',
     'b1bfee83fd74613fc70e614075302b94bf4471540cbd8465a25131cb9ab46436',
     '7552e5c9f9324774b4fb566045cbf98566e0d5f3d16a664049acce5a47dbe854'),
)
TYPED_EXPORT_FILES += (('src/json-symtab-language/json_goto_function.cpp', 'd3dd200f2ba15be29ac6a7832d82c2d119febb0b02ef4fbceaea51259adee071', '647f2910a4498f1b3b9efcfaf55e070f2a6b4fd9cc3c90f0df890453ad4d0b0c'), ('src/goto-instrument/goto_instrument_parse_options.cpp', '99f91f53a59e5b3702fa1a7a17f49cb85a9d0448f30d474383a6fb825165c322', 'f897abfee7cc85eccb62105e55d263cbf80131eaf00821bdba44184a0a09d071'), ('src/goto-instrument/goto_instrument_parse_options.h', '9fafc2d72b51d5a5694aaf439af92c2fd98f3145bcda05d46135de1abc88d5a3', 'b1fd5eb0aca7e4b3aaa3d6a39d0ca1d0b910fb53646cbba666523ba311779ae3'))
FRONTEND_PATCH = PATCH.with_name('cbmc-6.11.0-c-null-pointer-constant.patch')
FRONTEND_PATCH_SHA256 = '313b4dd202fb192c51226ffe1cd2c77d2834de4bf860265da293057761886f32'
FRONTEND_ORIGINAL_SHA256 = '0769bc82fd3edbeb5147502cf3c64cadca5afb099fb4a993da576d1ce3f4ef40'
FRONTEND_PATCHED_SHA256 = '5d214f7de60dc696a990e91d39e39d55b74fed78ac3365f0a8967c01f1e207b6'
GENERIC_PATCH = PATCH.with_name('cbmc-6.11.0-generic-qualifiers.patch')
GENERIC_PATCH_SHA256 = 'fee80742833ad01e46a4679feee5ce9597c15bf7fb5974dad7cd322711cbc6c7'
GENERIC_PATCHED_SHA256 = '29f466b67358f4ec0433bb69469816e871b4bd982ced82cfb0640f6861a380df'
DECAY_PATCH = PATCH.with_name('cbmc-6.11.0-generic-array-decay.patch')
DECAY_PATCH_SHA256 = '2c88cc612880ab2db1c8c30fa910ac9a077e9be6573a5ac8890d004413149605'
DECAY_PATCHED_SHA256 = '32761042f76bb1d084bf85edf6aab8eae8fcc467c8e91778cb2cd2d6482712ce'
POINTER_DIFFERENCE_PATCH = PATCH.with_name('cbmc-6.11.0-pointer-difference-overflow.patch')
POINTER_DIFFERENCE_PATCH_SHA256 = 'f86b41bdd2981cb1448f625fb5805d84c5c7cff2b815d37556d1c46f85886c54'
POINTER_DIFFERENCE_FILES = (
    ('src/ansi-c/goto-conversion/goto_check_c.cpp',
     'e7a60aef26b380599191f4d75b9e8df5c1d6d8a041b555b0ed829f142a083b05',
     '5f8a47ecd1c41b80bf77c176121ca5501c15ded53e641e3798d384ebf7d80bee'),
    ('src/ansi-c/goto-conversion/pointer_difference_overflow.h', None,
     'ed4164b8260b5df913caea5c123a264deb916534abc62e317242cf49aaa76739'),
    ('src/util/simplify_expr_pointer.cpp',
     '854ce28f53d465fbf5c16c81b49b6988552152cba571ba89aa74934a7c332f00',
     '8296bc5632944518832b5281f23ae5735b4ce989be349127ebc7f223bc1e34ed'),
    ('src/goto-symex/simplify_expr_with_value_set.cpp',
     'e6dd7a7308ef9c61d78528c151b99988c043c07cf7df1965c5ff476cd513c493',
     '65b6bdee455cde065c6d4df4c21c3e4b386e89c75aeed06d2f9f02376eb7c65c'),
)


def checksum(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def require_pin(path, expected):
    if not Path(path).is_file() or checksum(path) != expected:
        raise ValueError('input differs from pinned bytes: ' + str(path))


def run(command, log, cwd=None, timeout=3600):
    with log.open('wb') as stream:
        process = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, cwd=cwd, timeout=timeout)
    if process.returncode:
        raise ValueError('backend build command failed; see ' + str(log))


def build(prefix, source_archive, solver_archive, base_toolchain, jobs=2, *, c_frontend=False,
          pointer_difference_overflow=False):
    if os.name != 'posix':
        raise ValueError('run this builder on the native Linux build host')
    if type(jobs) is not int or not 1 <= jobs <= 16:
        raise ValueError('jobs must be between 1 and 16')
    prefix = Path(prefix).resolve()
    if prefix.exists():
        raise ValueError('use a new private output prefix')
    for path, expected in ((source_archive, SOURCE_SHA256), (solver_archive, SOLVER_SHA256),
                           (PATCH, PATCH_SHA256), (JSON_PATCH, JSON_PATCH_SHA256),
                           (TYPED_EXPORT_PATCH, TYPED_EXPORT_PATCH_SHA256)):
        require_pin(path, expected)
    if c_frontend:
        require_pin(FRONTEND_PATCH, FRONTEND_PATCH_SHA256)
        require_pin(GENERIC_PATCH, GENERIC_PATCH_SHA256)
        require_pin(DECAY_PATCH, DECAY_PATCH_SHA256)
    if pointer_difference_overflow:
        require_pin(POINTER_DIFFERENCE_PATCH, POINTER_DIFFERENCE_PATCH_SHA256)
    tc = Toolchain.load(base_toolchain)
    if tc.wsl_distribution:
        raise ValueError('base toolchain must be native to this Linux host')
    base_versions = tc.versions()
    if not base_versions['cbmc']['version'].startswith('6.11.0'):
        raise ValueError('this patch requires the CBMC 6.11.0 toolchain')
    prefix.mkdir(parents=True)
    archives = prefix / 'archives'
    archives.mkdir()
    for source, name in ((source_archive, 'cbmc-6.11.0.tar.gz'), (solver_archive, 'minisat2_2.2.1.orig.tar.gz'),
                         (PATCH, PATCH.name), (JSON_PATCH, JSON_PATCH.name),
                         (TYPED_EXPORT_PATCH, TYPED_EXPORT_PATCH.name)):
        shutil.copyfile(source, archives / name)
    with tarfile.open(archives / 'cbmc-6.11.0.tar.gz') as archive:
        archive.extractall(prefix, filter='data')
    source = prefix / 'cbmc-cbmc-6.11.0'
    patched = source / 'src/goto-symex/shadow_memory_util.cpp'
    require_pin(patched, ORIGINAL_FILE_SHA256)
    patch_command = ['patch', '--batch', '--forward', '-p1', '-i', str(archives / PATCH.name)]
    run(patch_command, prefix / 'patch.log', source, 30)
    require_pin(patched, PATCHED_FILE_SHA256)
    patch_commands = [patch_command]
    patched_files = [patched]
    patch_logs = [prefix / 'patch.log']
    serializer = source / 'src/util/json.cpp'
    require_pin(serializer, JSON_ORIGINAL_SHA256)
    command = ['patch', '--batch', '--forward', '-p1', '-i', str(archives / JSON_PATCH.name)]
    log = prefix / 'json-patch.log'
    run(command, log, source, 30)
    require_pin(serializer, JSON_PATCHED_SHA256)
    patch_commands.append(command)
    patched_files.append(serializer)
    patch_logs.append(log)
    for relative, before, _ in TYPED_EXPORT_FILES:
        require_pin(source / relative, before)
    command = ['patch', '--batch', '--forward', '-p1', '-i', str(archives / TYPED_EXPORT_PATCH.name)]
    log = prefix / 'typed-export-patch.log'
    run(command, log, source, 30)
    for relative, _, after in TYPED_EXPORT_FILES:
        require_pin(source / relative, after)
        patched_files.append(source / relative)
    patch_commands.append(command)
    patch_logs.append(log)
    if c_frontend:
        shutil.copyfile(FRONTEND_PATCH, archives / FRONTEND_PATCH.name)
        frontend = source / 'src/ansi-c/c_typecheck_expr.cpp'
        require_pin(frontend, FRONTEND_ORIGINAL_SHA256)
        command = ['patch', '--batch', '--forward', '-p1', '-i', str(archives / FRONTEND_PATCH.name)]
        log = prefix / 'frontend-patch.log'
        run(command, log, source, 30)
        require_pin(frontend, FRONTEND_PATCHED_SHA256)
        patch_commands.append(command)
        patched_files.append(frontend)
        patch_logs.append(log)
        for extra, expected, name in ((GENERIC_PATCH, GENERIC_PATCHED_SHA256, 'generic-patch.log'),
                                      (DECAY_PATCH, DECAY_PATCHED_SHA256, 'decay-patch.log')):
            shutil.copyfile(extra, archives / extra.name)
            command = ['patch', '--batch', '--forward', '-p1', '-i', str(archives / extra.name)]
            log = prefix / name
            run(command, log, source, 30)
            require_pin(frontend, expected)
            patch_commands.append(command)
            patch_logs.append(log)
    if pointer_difference_overflow:
        for relative, before, _ in POINTER_DIFFERENCE_FILES:
            path = source / relative
            if before is None:
                if path.exists() or path.is_symlink():
                    raise ValueError('new backend header already exists: ' + str(path))
            else:
                require_pin(path, before)
        shutil.copyfile(POINTER_DIFFERENCE_PATCH, archives / POINTER_DIFFERENCE_PATCH.name)
        command = ['patch', '--batch', '--forward', '-p1', '-i', str(archives / POINTER_DIFFERENCE_PATCH.name)]
        log = prefix / 'pointer-difference-patch.log'
        run(command, log, source, 30)
        for relative, _, after in POINTER_DIFFERENCE_FILES:
            path = source / relative
            require_pin(path, after)
            patched_files.append(path)
        patch_commands.append(command)
        patch_logs.append(log)
    build_dir = prefix / 'build'
    cache = build_dir / 'minisat2-download/minisat2-download-prefix/src'
    cache.mkdir(parents=True)
    shutil.copyfile(archives / 'minisat2_2.2.1.orig.tar.gz', cache / 'minisat2_2.2.1.orig.tar.gz')
    configure = ['cmake', '-S', str(source), '-B', str(build_dir), '-DWITH_JBMC=OFF', '-Denable_cbmc_tests=OFF']
    targets = ['cbmc', 'goto-cc', 'goto-instrument', 'symtab2gb']
    compile_ = ['cmake', '--build', str(build_dir), '--target', *targets, '-j' + str(jobs)]
    run(configure, prefix / 'configure.log', timeout=180)
    run(compile_, prefix / 'build.log')
    bin_dir = prefix / 'toolchain-bin'
    bin_dir.mkdir()
    for name in targets:
        origin = build_dir / 'bin' / name
        shutil.copyfile(origin, bin_dir / name)
        (bin_dir / name).chmod(0o755)
    config = prefix / 'toolchain.json'
    config.write_text(json.dumps({'bin_dir': str(bin_dir)}, indent=2) + '\n')
    if tc.versions() != base_versions:
        raise ValueError('base toolchain changed during source build')
    require_pin(patched, PATCHED_FILE_SHA256)
    require_pin(serializer, JSON_PATCHED_SHA256)
    for relative, _, after in TYPED_EXPORT_FILES:
        require_pin(source / relative, after)
    if c_frontend:
        require_pin(frontend, DECAY_PATCHED_SHA256)
    if pointer_difference_overflow:
        for relative, _, after in POINTER_DIFFERENCE_FILES:
            require_pin(source / relative, after)
    manifest = {'schema': 1, 'kind': 'vulgate-patched-shadow-backend',
                'implementation_sha256': checksum(__file__), 'base_tools': base_versions,
                'tools': Toolchain.load(config).versions(),
                'json_control_escaping_correction': True,
                'typed_export_capabilities': {
                    'functions': {'irepCommentsIncluded': True, 'sourceLocationIrepIncluded': True},
                    'symbolTableWrapper': {'irepCommentsIncluded': True, 'symbolLocationIrepIncluded': True}},
                'typed_transport_capabilities': {
                    'raw_functions_option': '--show-goto-functions-raw',
                    'raw_symbols_option': '--show-symbol-table-raw',
                    'preserved_instruction_code': ['SKIP', 'SET_RETURN_VALUE']},
                'c_frontend_correction': c_frontend,
                'pointer_difference_overflow_correction': pointer_difference_overflow,
                'commands': [*patch_commands, configure, compile_],
                'assets': {p.relative_to(prefix).as_posix(): checksum(p) for p in
                           [config, *patched_files, *archives.iterdir(), *bin_dir.iterdir(),
                            *patch_logs, prefix / 'configure.log', prefix / 'build.log']},
                'scope': ('Pinned source correction and binary identity; regression qualification is separate. '
                          'Whole-model import requires a typed transport adapter and actual-model roundtrip qualification.')}
    path = prefix / 'backend-manifest.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    return {'manifest': str(path), 'manifest_sha256': checksum(path), 'toolchain': str(config)}


def check(prefix, pin):
    prefix = Path(prefix).resolve()
    path = prefix / 'backend-manifest.json'
    require_pin(path, pin)
    data = json.loads(path.read_text())
    if data.get('kind') != 'vulgate-patched-shadow-backend' or data.get('implementation_sha256') != checksum(__file__):
        raise ValueError('backend manifest or builder revision differs')
    for name, expected in data['assets'].items():
        asset = (prefix / name).resolve()
        if not asset.is_relative_to(prefix):
            raise ValueError('backend asset escapes the private prefix')
        require_pin(asset, expected)
    if Toolchain.load(prefix / 'toolchain.json').versions() != data['tools']:
        raise ValueError('backend executable identity differs')
    return {'status': 'CURRENT_BACKEND_BYTES', 'manifest_sha256': pin}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--cbmc-archive', type=Path)
    parser.add_argument('--minisat-archive', type=Path)
    parser.add_argument('--base-toolchain', type=Path)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--c-frontend', action='store_true', help='also build the C type-semantics corrections')
    parser.add_argument('--pointer-difference-overflow', action='store_true',
                        help='also build the candidate pointer-difference range correction in all four tools')
    parser.add_argument('--check-sha256')
    args = parser.parse_args()
    if args.check_sha256:
        result = check(args.prefix, args.check_sha256)
    else:
        if not all((args.cbmc_archive, args.minisat_archive, args.base_toolchain)):
            parser.error('building requires both pinned archives and --base-toolchain')
        result = build(args.prefix, args.cbmc_archive, args.minisat_archive, args.base_toolchain, args.jobs,
                       c_frontend=args.c_frontend, pointer_difference_overflow=args.pointer_difference_overflow)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
