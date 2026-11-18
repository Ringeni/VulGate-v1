"""Task specification; all program-specific behavior remains in C inputs."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re


class SpecificationError(ValueError):
    pass


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise SpecificationError(f"invalid C identifier: {value!r}")
    return value


@dataclass(frozen=True)
class EnvironmentSummary:
    """An explicitly assumed body for one original function definition."""
    translation_unit: Path
    function: str
    body_file: Path
    assumption: str

    def to_dict(self):
        return {"translation_unit": str(self.translation_unit), "function": self.function,
                "body_file": str(self.body_file), "assumption": self.assumption}

    @classmethod
    def from_dict(cls, value, directory):
        if not isinstance(value, dict) or set(value) != {"translation_unit", "function", "body_file", "assumption"}:
            raise SpecificationError("environment entries require translation_unit, function, body_file and assumption")
        if any(not isinstance(value[key], str) or not value[key].strip()
               for key in ("translation_unit", "body_file", "assumption")):
            raise SpecificationError("environment paths and assumptions must be nonempty strings")
        unit = (directory / value["translation_unit"]).resolve()
        body = (directory / value["body_file"]).resolve()
        if not unit.is_file() or not body.is_file():
            raise SpecificationError("environment translation unit and body file must exist")
        return cls(unit, identifier(value["function"]), body, value["assumption"])


@dataclass(frozen=True)
class Task:
    path: Path
    sources: tuple[Path, ...]
    entry: str
    targets: tuple[str, ...]
    include_dirs: tuple[Path, ...] = ()
    defines: tuple[str, ...] = ()
    unwind: int = 16
    timeout: int = 60
    memory_cleanup: bool = True
    compilation_database: Path | None = None
    units: tuple[dict, ...] = ()
    command_syntax: str = "auto"
    object_bits: int = 8
    environment: tuple[EnvironmentSummary, ...] = ()

    @classmethod
    def load(cls, path):
        path = Path(path).resolve()
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = {"schema", "sources", "entry", "targets", "include_dirs", "defines",
                   "unwind", "timeout", "memory_cleanup", "compilation_database", "units", "command_syntax", "object_bits", "environment"}
        if not isinstance(data, dict) or set(data) - allowed or data.get("schema") != 1:
            raise SpecificationError("expected task schema 1 with supported fields")
        for required in ("sources", "entry", "targets"):
            if required not in data:
                raise SpecificationError(f"missing field {required}")

        def paths(key, directories=False):
            values = data.get(key, [])
            if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                raise SpecificationError(f"{key} must be a list of paths")
            result = tuple((path.parent / v).resolve() for v in values)
            if len(set(result)) != len(result):
                raise SpecificationError(f"duplicate {key}")
            if any(not (p.is_dir() if directories else p.is_file()) for p in result):
                raise SpecificationError(f"missing {key} path")
            return result

        sources = paths("sources")
        if not sources:
            raise SpecificationError("at least one C source is required")
        targets = data["targets"]
        if (not isinstance(targets, list) or not targets or
                any(not isinstance(s, str) or not s for s in targets) or len(set(targets)) != len(targets)):
            raise SpecificationError("targets must be distinct exact assertion descriptions")
        defines = data.get("defines", [])
        if not isinstance(defines, list) or any(not isinstance(s, str) or "\n" in s for s in defines):
            raise SpecificationError("defines must contain single-line preprocessor definitions")
        for key, default in (("unwind", 16), ("timeout", 60)):
            if type(data.get(key, default)) is not int or not 1 <= data.get(key, default) <= 3600:
                raise SpecificationError(f"{key} must be an integer in 1..3600")
        if type(data.get("memory_cleanup", True)) is not bool:
            raise SpecificationError("memory_cleanup must be boolean")
        if type(data.get("object_bits", 8)) is not int or not 1 <= data.get("object_bits", 8) <= 32:
            raise SpecificationError("object_bits must be an integer in 1..32")
        database = data.get("compilation_database")
        if database is not None:
            if not isinstance(database, str) or not (path.parent / database).is_file():
                raise SpecificationError("compilation_database must name an existing JSON file")
            database = (path.parent / database).resolve()
        units = data.get("units", [])
        if not isinstance(units, list) or any(not isinstance(u, dict) or "source" not in u or
                set(u) - {"source", "directory", "compiler", "flags", "output"} for u in units):
            raise SpecificationError("unsupported per-unit configuration")
        for unit in units:
            for field in ("source", "directory", "compiler", "output"):
                if field in unit and not isinstance(unit[field], str):
                    raise SpecificationError(f"unit {field} must be a string")
            if "flags" in unit and (not isinstance(unit["flags"], list) or any(not isinstance(f, str) for f in unit["flags"])):
                raise SpecificationError("unit flags must be an array of arguments")
        syntax = data.get("command_syntax", "auto")
        if syntax not in ("auto", "posix", "windows"):
            raise SpecificationError("command_syntax must be auto, posix or windows")
        environment = data.get("environment", [])
        if not isinstance(environment, list):
            raise SpecificationError("environment must be a list of explicit function summaries")
        environment = tuple(EnvironmentSummary.from_dict(item, path.parent) for item in environment)
        keys = [(item.translation_unit, item.function) for item in environment]
        if len(keys) != len(set(keys)):
            raise SpecificationError("duplicate environment function summary")
        if any(item.translation_unit not in sources or item.function == data["entry"] for item in environment):
            raise SpecificationError("environment functions must belong to task sources and must not be the root")
        return cls(path, sources, identifier(data["entry"]), tuple(targets), paths("include_dirs", True),
                   tuple(defines), data.get("unwind", 16), data.get("timeout", 60),
                   data.get("memory_cleanup", True), database, tuple(units), syntax, data.get("object_bits", 8), environment)

    def semantic_spec(self):
        return {"entry": self.entry, "targets": self.targets, "defines": self.defines,
                "sources": [str(p) for p in self.sources],
                "include_dirs": [str(p) for p in self.include_dirs],
                "unwind": self.unwind, "memory_cleanup": self.memory_cleanup,
                "compilation_database": str(self.compilation_database) if self.compilation_database else None,
                "units": self.units, "command_syntax": self.command_syntax, "object_bits": self.object_bits,
                **({"environment": [item.to_dict() for item in self.environment]} if self.environment else {})}


@dataclass(frozen=True)
class Policy:
    name: str
    translation_unit: Path
    function: str
    return_value: int | None
    guard: dict

    @property
    def return_actions(self):
        return (self.return_value,)

    def to_dict(self):
        return {"id": self.name, "translation_unit": str(self.translation_unit), "function": self.function,
                "return": self.return_value, "guard": self.guard}

    @classmethod
    def load_many(cls, path):
        path = Path(path).resolve()
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) != {"schema", "policies"} or data["schema"] != 1:
            raise SpecificationError("expected policies schema 1")
        if not isinstance(data["policies"], list):
            raise SpecificationError("policies must be a list")
        result = []
        for item in data["policies"]:
            if isinstance(item, dict) and "family" in item:
                result.append(FamilyPolicy.from_dict(item, path.parent))
                continue
            if isinstance(item, dict) and "table" in item:
                result.append(TablePolicy.from_dict(item, path.parent))
                continue
            if not isinstance(item, dict) or set(item) != {"id", "translation_unit", "function", "return", "guard"}:
                raise SpecificationError("unsupported policy fields")
            if item["return"] is not None and (type(item["return"]) is not int or not -(2**63) <= item["return"] < 2**63):
                raise SpecificationError("return must be null (void) or a signed 64-bit integer")
            if not isinstance(item["translation_unit"], str):
                raise SpecificationError("translation_unit must be a path")
            result.append(cls(identifier(item["id"]), (path.parent / item["translation_unit"]).resolve(),
                              identifier(item["function"]), item["return"], item["guard"]))
        if len({p.name for p in result}) != len(result):
            raise SpecificationError("policy IDs must be unique")
        if len({(p.translation_unit, p.function) for p in result}) != len(result):
            raise SpecificationError("one combined guard per function entry is required")
        return result


@dataclass(frozen=True)
class TablePolicy:
    """A total, finite observation table: decision 0 is PASS, k>0 returns actions[k-1]."""
    name: str
    translation_unit: Path
    function: str
    predicates: tuple[dict, ...]
    return_actions: tuple[int | None, ...]
    decisions: tuple[int, ...]

    def __post_init__(self):
        from .expression import compile_expression
        identifier(self.name)
        identifier(self.function)
        if len(self.predicates) > 8:
            raise SpecificationError("at most 8 Boolean observation predicates per entry")
        for predicate in self.predicates:
            compile_expression(predicate)
        if not self.return_actions or len(self.return_actions) > 16:
            raise SpecificationError("table requires 1..16 return actions")
        if any(value is not None and (type(value) is not int or not -(2**63) <= value < 2**63)
               for value in self.return_actions):
            raise SpecificationError("table return actions must be null or signed 64-bit integers")
        if len(set(self.return_actions)) != len(self.return_actions):
            raise SpecificationError("duplicate return actions")
        if len(self.decisions) != 2**len(self.predicates) or any(
                type(value) is not int or not 0 <= value <= len(self.return_actions) for value in self.decisions):
            raise SpecificationError("one valid decision is required for each observation region")

    def to_dict(self):
        return {"id": self.name, "translation_unit": str(self.translation_unit), "function": self.function,
                "table": {"predicates": list(self.predicates), "returns": list(self.return_actions),
                          "decisions": list(self.decisions)}}

    @classmethod
    def from_dict(cls, item, directory):
        if set(item) != {"id", "translation_unit", "function", "table"} or not isinstance(item["table"], dict):
            raise SpecificationError("unsupported table policy fields")
        table = item["table"]
        if set(table) != {"predicates", "returns", "decisions"} or any(
                not isinstance(table[field], list) for field in table):
            raise SpecificationError("table requires predicates, returns and decisions arrays")
        if not isinstance(item["translation_unit"], str):
            raise SpecificationError("translation_unit must be a path")
        return cls(identifier(item["id"]), (directory / item["translation_unit"]).resolve(),
                   identifier(item["function"]), tuple(table["predicates"]),
                   tuple(table["returns"]), tuple(table["decisions"]))


@dataclass(frozen=True)
class FamilyPolicy:
    """Nonempty action domains per observation region, with explicit choice lifetime."""
    name: str
    translation_unit: Path
    function: str
    predicates: tuple[dict, ...]
    return_actions: tuple[int | None, ...]
    domains: tuple[tuple[int, ...], ...]
    selection: str = "fixed_table"

    def __post_init__(self):
        if self.selection not in ("fixed_table", "per_invocation"):
            raise SpecificationError("family selection must be fixed_table or per_invocation")
        if len(self.predicates) > 8:
            raise SpecificationError("at most 8 Boolean observation predicates per entry")
        if len(self.domains) != 2**len(self.predicates) or any(not d or
                any(type(v) is not int or not 0 <= v <= len(self.return_actions) for v in d) or
                len(set(d)) != len(d) for d in self.domains):
            raise SpecificationError("each observation region requires a nonempty, distinct, valid action domain")
        TablePolicy(self.name, self.translation_unit, self.function, self.predicates, self.return_actions,
                    tuple(d[0] for d in self.domains))

    def to_dict(self):
        return {"id": self.name, "translation_unit": str(self.translation_unit), "function": self.function,
                "family": {"predicates": list(self.predicates), "returns": list(self.return_actions),
                           "domains": [list(d) for d in self.domains], "selection": self.selection}}

    @classmethod
    def from_dict(cls, item, directory):
        if set(item) != {"id", "translation_unit", "function", "family"} or not isinstance(item["family"], dict):
            raise SpecificationError("unsupported policy-family fields")
        family = item["family"]
        if (set(family) != {"predicates", "returns", "domains", "selection"} or
                any(not isinstance(family[k], list) for k in ("predicates", "returns", "domains")) or
                any(not isinstance(d, list) for d in family["domains"]) or not isinstance(item["translation_unit"], str)):
            raise SpecificationError("family requires predicates, returns, domains and selection")
        return cls(identifier(item["id"]), (directory / item["translation_unit"]).resolve(),
                   identifier(item["function"]), tuple(family["predicates"]), tuple(family["returns"]),
                   tuple(tuple(d) for d in family["domains"]), family["selection"])
