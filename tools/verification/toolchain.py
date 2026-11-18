"""Local/WSL tool invocation with bounded execution and exact argv logging."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from .spec import SpecificationError


@dataclass
class ProcessResult:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False

    def to_dict(self):
        return asdict(self)


@dataclass
class FileProcessResult:
    argv: list[str]
    returncode: int | None
    stdout_path: str
    stderr_path: str
    timed_out: bool = False

    def to_dict(self):
        return asdict(self)


@dataclass
class Toolchain:
    bin_dir: str = ""
    wsl_distribution: str | None = None

    @classmethod
    def load(cls, path=None):
        if path is None:
            return cls()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) - {"bin_dir", "wsl_distribution"}:
            raise SpecificationError("unsupported toolchain configuration")
        if not isinstance(data.get("bin_dir", ""), str):
            raise SpecificationError("bin_dir must be a string")
        if data.get("wsl_distribution") is not None and not isinstance(data["wsl_distribution"], str):
            raise SpecificationError("wsl_distribution must be a string")
        return cls(**data)

    def path(self, path):
        path = str(Path(path).resolve())
        if self.wsl_distribution:
            match = re.match(r"^([A-Za-z]):[/\\](.*)$", path)
            if match is None:
                raise SpecificationError("WSL backend requires Windows drive paths")
            return "/mnt/" + match[1].lower() + "/" + match[2].replace("\\", "/")
        return path

    def executable(self, tool):
        if self.bin_dir:
            return self.bin_dir.rstrip("/\\") + "/" + tool + (".exe" if os.name == "nt" and not self.wsl_distribution else "")
        found = tool if self.wsl_distribution else shutil.which(tool)
        if not found:
            raise SpecificationError(f"required executable not found: {tool}")
        return found

    def run(self, tool, args, timeout=60, *, cwd=None):
        return self.run_external(self.executable(tool), args, timeout, cwd=cwd)

    def run_to_files(self, tool, args, stdout_path, stderr_path, timeout=60, *, cwd=None):
        """Retain complete export bytes without capturing/requoting huge strings."""
        command = [self.executable(tool), *[self.path(a) if isinstance(a, Path) else str(a) for a in args]]
        if self.wsl_distribution:
            command = ['wsl', '-d', self.wsl_distribution,
                       *(['--cd', self.path(cwd)] if cwd is not None else []), '--exec',
                       'timeout', '--signal=TERM', '--kill-after=2s', f'{timeout}s', *command]
        with Path(stdout_path).open('xb') as out, Path(stderr_path).open('xb') as err:
            try:
                process = subprocess.run(command, stdout=out, stderr=err,
                    timeout=timeout + (10 if self.wsl_distribution else 0),
                    cwd=None if self.wsl_distribution or cwd is None else str(cwd))
                return FileProcessResult(command, process.returncode, str(stdout_path), str(stderr_path),
                    self.wsl_distribution is not None and process.returncode in (124, 137))
            except subprocess.TimeoutExpired:
                return FileProcessResult(command, None, str(stdout_path), str(stderr_path), True)

    def run_external(self, executable, args, timeout=60, *, cwd=None):
        command = [str(executable), *[self.path(a) if isinstance(a, Path) else str(a) for a in args]]
        if self.wsl_distribution:
            command = ["wsl", "-d", self.wsl_distribution,
                       *(["--cd", self.path(cwd)] if cwd is not None else []), "--exec", "timeout", "--signal=TERM",
                       "--kill-after=2s", f"{timeout}s", *command]
        try:
            process = subprocess.run(command, capture_output=True, timeout=timeout + (10 if self.wsl_distribution else 0),
                                     cwd=None if self.wsl_distribution or cwd is None else str(cwd))
            return ProcessResult(command, process.returncode,
                                 process.stdout.decode("utf-8", errors="replace"),
                                 process.stderr.decode("utf-8", errors="replace"),
                                 self.wsl_distribution is not None and process.returncode in (124, 137))
        except subprocess.TimeoutExpired as exc:
            return ProcessResult(command, None, (exc.stdout or b"").decode("utf-8", errors="replace"),
                                 (exc.stderr or b"").decode("utf-8", errors="replace"), True)

    def native_compiler(self, compiler, directory):
        """Resolve and fingerprint the compiler on the actual execution host."""
        if self.wsl_distribution:
            if "\\" in compiler or re.match(r"^[A-Za-z]:", compiler) or compiler.endswith(".exe"):
                raise SpecificationError("a Windows compiler command requires a native Windows backend")
            found = self.run_external("which", [compiler], 15, cwd=directory)
            if found.returncode != 0 or found.timed_out:
                raise SpecificationError(f"native compiler not found on the WSL host: {compiler}")
            resolved = self.run_external("readlink", ["-f", found.stdout.strip()], 15, cwd=directory)
            if resolved.returncode != 0 or resolved.timed_out:
                raise SpecificationError("cannot resolve native compiler identity")
            executable = resolved.stdout.strip()
            fingerprint = self.run_external("sha256sum", [executable], 30)
            if fingerprint.returncode != 0 or fingerprint.timed_out or not fingerprint.stdout.split():
                raise SpecificationError("cannot fingerprint native compiler")
            checksum = fingerprint.stdout.split()[0]
        else:
            executable = shutil.which(compiler)
            if executable is None:
                raise SpecificationError(f"native compiler not found: {compiler}")
            executable = str(Path(executable).resolve())
            checksum = sha256(Path(executable).read_bytes()).hexdigest()
        version = self.run_external(executable, ["--version"], 15, cwd=directory)
        if version.returncode != 0 or version.timed_out or not version.stdout.strip() or not re.fullmatch("[a-f0-9]{64}", checksum):
            raise SpecificationError("cannot establish native compiler identity")
        return {"executable": executable, "sha256": checksum, "version": version.stdout.strip()}

    def versions(self):
        result = {}
        for name in ("goto-cc", "goto-instrument", "cbmc", "symtab2gb"):
            process = self.run(name, ["--help" if name == "symtab2gb" else "--version"], 15)
            if process.returncode != 0 or process.timed_out:
                raise SpecificationError(f"cannot run {name}: {process.stdout} {process.stderr}")
            version = (next((line.strip() for line in process.stdout.splitlines() if "symtab2gb " in line and "64-bit" in line), "")
                       if name == "symtab2gb" else process.stdout.strip())
            if not version:
                raise SpecificationError(f"cannot identify {name} version")
            result[name] = {"executable": self.executable(name), "version": version}
        if self.wsl_distribution:
            try:
                process = subprocess.run(["wsl", "-d", self.wsl_distribution, "--exec", "timeout", "--signal=TERM",
                                          "--kill-after=2s", "30s", "sha256sum",
                                          *[value["executable"] for value in result.values()]],
                                         capture_output=True, timeout=40)
            except subprocess.TimeoutExpired as exc:
                raise SpecificationError("WSL toolchain fingerprint query timed out") from exc
            if process.returncode in (124, 137):
                raise SpecificationError("WSL toolchain fingerprint query timed out")
            lines = process.stdout.decode("utf-8", errors="strict").splitlines()
            if process.returncode != 0 or len(lines) != len(result):
                raise SpecificationError("cannot fingerprint WSL toolchain executables")
            for value, line in zip(result.values(), lines):
                digest = line.split(maxsplit=1)[0]
                if not re.fullmatch("[0-9a-f]{64}", digest):
                    raise SpecificationError("invalid toolchain fingerprint")
                value["sha256"] = digest
        else:
            for value in result.values():
                value["sha256"] = sha256(Path(value["executable"]).read_bytes()).hexdigest()
        return result
