"""A C-typed, expression-only policy language with no writes or calls."""
from .spec import SpecificationError, identifier


def compile_expression(node):
    budget = [512]
    variables = set()

    def emit(item, depth):
        budget[0] -= 1
        if not isinstance(item, dict) or depth > 32 or budget[0] < 0:
            raise SpecificationError("invalid or oversized policy expression")
        keys = set(item)
        if keys == {"const"}:
            value = item["const"]
            if type(value) is bool:
                return "1" if value else "0"
            if type(value) is not int or not -(2**63) <= value < 2**63:
                raise SpecificationError("constant is outside the supported integer domain")
            if value == -(2**63):
                return "(-9223372036854775807LL - 1LL)"
            # Small literals have C int type; preserve that in comparisons.
            return f"({value}{'LL' if not -(2**31) <= value < 2**31 else ''})"
        if keys == {"var"}:
            name = identifier(item["var"])
            if name.startswith(("__CPROVER", "__vulgate_")):
                raise SpecificationError("instrumentation identifiers are not policy observations")
            variables.add(name)
            return name
        if keys == {"base", "field", "pointer"}:
            field = identifier(item["field"])
            if type(item["pointer"]) is not bool:
                raise SpecificationError("pointer field selector must be boolean")
            return f"({emit(item['base'], depth + 1)}){'->' if item['pointer'] else '.'}{field}"
        if keys == {"base", "index"}:
            return f"({emit(item['base'], depth + 1)})[{emit(item['index'], depth + 1)}]"
        if keys == {"op", "args"}:
            args = item["args"]
            if not isinstance(args, list):
                raise SpecificationError("operator args must be an array")
            op = item["op"]
            if len(args) == 1 and op in ("!", "~", "-", "*"):
                return f"({op}({emit(args[0], depth + 1)}))"
            if len(args) == 2 and op in ("==", "!=", "<", "<=", ">", ">=", "&&", "||",
                                        "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"):
                return f"({emit(args[0], depth + 1)} {op} {emit(args[1], depth + 1)})"
        raise SpecificationError("expression permits only constants, reads, and pure operators")

    return emit(node, 0), sorted(variables)
