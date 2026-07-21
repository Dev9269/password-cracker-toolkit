import re
import os


DEFAULT_RULES_NAME = "best64.rule"
DEFAULT_RULES = [
    ":",
    "l",
    "u",
    "c",
    "t",
    "r",
    "d",
    "f",
    "{",
    "}",
    "$1",
    "$2",
    "$3",
    "$!",
    "^1",
    "^2",
    "^!",
    "s0@",
    "s0$",
    "s0!",
    "so0",
    "sa@",
    "se3",
    "si1",
    "so0",
    "ss5",
    "st7",
    "i4a",
    "i4e",
    "i4i",
    "i4o",
    "i4s",
    "@",
    "@@",
    "u $1",
    "u $2",
    "c $1",
    "d $1",
    "r $1",
    "f $1",
]


def parse_rule(rule_str):
    commands = []
    i = 0
    while i < len(rule_str):
        c = rule_str[i]
        if c in ("l", "u", "c", "r", "d", "f", "{", "}", ":", "p", "E", "e"):
            commands.append((c, None))
            i += 1
        elif c == "t":
            commands.append(("t", None))
            i += 1
        elif c == "T":
            if i + 1 < len(rule_str):
                try:
                    pos = int(rule_str[i + 1])
                    commands.append(("T", pos))
                except ValueError:
                    commands.append(("T", None))
                i += 2
            else:
                i += 1
        elif c == "$":
            if i + 1 < len(rule_str):
                commands.append(("$", rule_str[i + 1]))
                i += 2
            else:
                commands.append(("$", ""))
                i += 1
        elif c == "^":
            if i + 1 < len(rule_str):
                commands.append(("^", rule_str[i + 1]))
                i += 2
            else:
                commands.append(("^", ""))
                i += 1
        elif c == "s":
            if i + 1 < len(rule_str):
                nxt = rule_str[i + 1]
                if nxt.isalnum():
                    old_c = nxt
                    new_c = rule_str[i + 2] if i + 2 < len(rule_str) else ""
                    commands.append(("s", (old_c, new_c)))
                    i += 3
                else:
                    sep = nxt
                    remaining = rule_str[i + 2 :]
                    try:
                        first_end = remaining.index(sep)
                        old_c = remaining[:first_end]
                        rest = remaining[first_end + 1 :]
                        second_end = rest.index(sep) if sep in rest else len(rest)
                        new_c = rest[:second_end]
                        commands.append(("s", (old_c, new_c)))
                        i += 2 + first_end + 1 + second_end + 1
                    except ValueError:
                        parts = remaining.split(sep, 1)
                        old_c = parts[0] if len(parts) > 0 else ""
                        new_c = parts[1] if len(parts) > 1 else ""
                        commands.append(("s", (old_c, new_c)))
                        i += 2 + len(old_c) + len(new_c)
            else:
                i += 1
        elif c == "@":
            commands.append(("@", None))
            i += 1
        elif c == "i":
            if i + 2 < len(rule_str):
                pos = rule_str[i + 1]
                ins_char = rule_str[i + 2]
                commands.append(("i", (pos, ins_char)))
                i += 3
            else:
                i += 1
        elif c == "o":
            if i + 2 < len(rule_str):
                pos = rule_str[i + 1]
                rep_char = rule_str[i + 2]
                commands.append(("o", (pos, rep_char)))
                i += 3
            else:
                i += 1
        elif c == "x":
            if i + 3 < len(rule_str):
                commands.append(("x", rule_str[i + 1 : i + 3]))
                i += 3
            else:
                i += 1
        elif c == "M":
            commands.append(("M", None))
            i += 1
        elif c == "D":
            commands.append(("D", None))
            i += 1
        elif c == " " or c == "\t":
            i += 1
        else:
            i += 1
    return commands


def apply_rule(word, commands):
    result = word
    for cmd, arg in commands:
        if cmd == ":":
            pass
        elif cmd == "l":
            result = result.lower()
        elif cmd == "u":
            result = result.upper()
        elif cmd == "c":
            result = result.capitalize() if result else result
        elif cmd == "t":
            result = result.swapcase() if result else result
        elif cmd == "T":
            if result and arg is not None and 0 <= arg < len(result):
                chars = list(result)
                chars[arg] = chars[arg].swapcase()
                result = "".join(chars)
        elif cmd == "r":
            result = result[::-1]
        elif cmd == "d":
            result = result + result
        elif cmd == "f":
            result = result + result[::-1] if result else result
        elif cmd == "{":
            if len(result) > 1:
                result = result[1:] + result[0]
        elif cmd == "}":
            if len(result) > 1:
                result = result[-1] + result[:-1]
        elif cmd == "$":
            result = result + arg
        elif cmd == "^":
            result = arg + result
        elif cmd == "s":
            old_c, new_c = arg
            result = result.replace(old_c, new_c, 1)
        elif cmd == "@":
            if result:
                result = result[1:]
        elif cmd == "i":
            if result:
                result = (
                    result[0].upper() + result[1:]
                    if result[0].islower()
                    else result[0].lower() + result[1:]
                )
        elif cmd == "o":
            result = result.swapcase()
        elif cmd == "x":
            try:
                pos = int(arg[0]) if len(arg) > 0 else 0
                count = int(arg[1]) if len(arg) > 1 else len(result)
                if 0 <= pos < len(result):
                    result = result[pos : pos + count]
            except (ValueError, IndexError):
                pass
        elif cmd == "M":
            if result:
                result = result.lower().capitalize()
        elif cmd == "D":
            if len(result) > 1:
                result = result[:-1]
    return result


def generate_rule_pipeline(word, rules):
    for rule_str in rules:
        commands = parse_rule(rule_str)
        yield apply_rule(word, commands)


def load_rules(filepath):
    rules = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append(line)
    return rules


def get_default_rules():
    return DEFAULT_RULES


def ensure_default_rules_file(path=None):
    if path is None:
        path = os.path.join(
            os.path.dirname(__file__), "..", "rules", DEFAULT_RULES_NAME
        )
    dirname = os.path.dirname(path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    if not os.path.exists(path):
        with open(path, "w") as f:
            for rule in DEFAULT_RULES:
                f.write(rule + "\n")
    return path
