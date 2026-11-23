"""cmdgate: decide allow / warn / block for a shell command an AI coding agent wants to run.

The command is parsed into the simple commands that would actually execute
(through chains, pipes, wrappers like sudo and xargs, `bash -c`, eval, and
command substitution) and each one is checked against structured rules.
Standard library only.
"""
import json
import os
import re
import sys

LEVEL = {"allow": 0, "warn": 1, "block": 2}
MAX_DEPTH = 8


class ParseError(ValueError):
    pass


# ---------------------------------------------------------------- lexer

_REDIR = re.compile(r"(?:\d+|&)?(?:>>|>&|>\||<<<|<<-?|<&|<>|>|<)")
_OPS = ("&&", "||", ";;", "|&", ";", "|", "&", "\n", "(", ")")


def _read_paren(s, i):
    """s[i:] starts just after '$('. Return (inner, index after the matching ')')."""
    depth, start, n = 1, i, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise ParseError("unterminated single quote")
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return s[start:i], i + 1
        i += 1
    raise ParseError("unterminated $(")


def _read_tick(s, i):
    start, n = i, len(s)
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == "`":
            return s[start:i], i + 1
        i += 1
    raise ParseError("unterminated backtick")


def lex(s):
    """Return tokens: ("w", text, [substitutions]), ("op", text) or ("redir", text)."""
    toks, buf, subs = [], None, []
    i, n = 0, len(s)

    def flush():
        nonlocal buf, subs
        if buf is not None:
            toks.append(("w", buf, subs))
            buf, subs = None, []

    while i < n:
        c = s[i]
        if c == "\\":
            if i + 1 >= n:
                raise ParseError("trailing backslash")
            if s[i + 1] != "\n":
                buf = (buf or "") + s[i + 1]
            i += 2
        elif c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise ParseError("unterminated single quote")
            buf = (buf or "") + s[i + 1:j]
            i = j + 1
        elif c == '"':
            buf = buf or ""
            i += 1
            while True:
                if i >= n:
                    raise ParseError("unterminated double quote")
                d = s[i]
                if d == '"':
                    i += 1
                    break
                if d == "\\" and i + 1 < n and s[i + 1] in '"\\$`\n':
                    if s[i + 1] != "\n":
                        buf += s[i + 1]
                    i += 2
                elif d == "$" and s[i + 1:i + 2] == "(":
                    inner, i = _read_paren(s, i + 2)
                    subs.append(inner)
                    buf += "$(" + inner + ")"
                elif d == "`":
                    inner, i = _read_tick(s, i + 1)
                    subs.append(inner)
                    buf += "`" + inner + "`"
                else:
                    buf += d
                    i += 1
        elif c == "$" and s[i + 1:i + 2] == "(":
            inner, i = _read_paren(s, i + 2)
            subs.append(inner)
            buf = (buf or "") + "$(" + inner + ")"
        elif c == "`":
            inner, i = _read_tick(s, i + 1)
            subs.append(inner)
            buf = (buf or "") + "`" + inner + "`"
        elif c in " \t":
            flush()
            i += 1
        elif c == "#" and buf is None:
            j = s.find("\n", i)
            i = n if j < 0 else j
        else:
            m = _REDIR.match(s, i) if (buf is None or c in "<>") else None
            if m:
                flush()
                toks.append(("redir", m.group(0)))
                i = m.end()
                continue
            for op in _OPS:
                if s.startswith(op, i):
                    flush()
                    toks.append(("op", op))
                    i += len(op)
                    break
            else:
                buf = (buf or "") + c
                i += 1
    flush()
    return toks


def pipelines(tokens):
    """Group tokens into pipelines, each a list of {"argv", "redirs", "subs"}."""
    out, pipe = [], []
    cmd = {"argv": [], "redirs": [], "subs": []}
    pending = None

    def end_cmd():
        nonlocal cmd
        if cmd["argv"] or cmd["redirs"] or cmd["subs"]:
            pipe.append(cmd)
        cmd = {"argv": [], "redirs": [], "subs": []}

    for t in tokens:
        if t[0] == "w":
            cmd["subs"].extend(t[2])
            if pending is not None:
                cmd["redirs"].append((pending, t[1]))
                pending = None
            else:
                cmd["argv"].append(t[1])
        elif t[0] == "redir":
            pending = t[1]
        else:
            pending = None
            end_cmd()
            if t[1] not in ("|", "|&"):
                if pipe:
                    out.append(pipe)
                pipe = []
    end_cmd()
    if pipe:
        out.append(pipe)
    return out


# ---------------------------------------------------------------- resolving what really runs

_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")
_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
# wrapper -> options that take a value
WRAPPERS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"}, "doas": {"-u", "-C"},
    "env": {"-u", "-C"}, "nohup": set(), "time": {"-f", "-o"}, "command": set(), "exec": {"-a"},
    "builtin": set(), "nice": {"-n"}, "ionice": {"-c", "-n", "-p"}, "timeout": {"-s", "-k"},
    "stdbuf": {"-i", "-o", "-e"}, "xargs": {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"},
    "busybox": set(), "setsid": set(), "watch": {"-n"},
}
# command -> options whose next argument is a value, so it is not a positional
VALUE_FLAGS = {
    "git": {"-C", "-c"},
    "kubectl": {"-n", "--namespace", "--context", "--kubeconfig", "-l", "--selector"},
    "psql": {"-h", "-U", "-d", "-p"},
    "mysql": {"-h", "-u", "-P", "-D"},
    "aws": {"--profile", "--region", "--endpoint-url"},
    "docker": {"-H", "--context"},
}


def _leaf(argv, redirs, via):
    name = os.path.basename(argv[0]) if argv else ""
    args = argv[1:]
    flags, pos = set(), []
    vf = VALUE_FLAGS.get(name, ())
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            pos.extend(args[i + 1:])
            break
        if a.startswith("--"):
            flags.add(a.split("=", 1)[0])
            if a in vf:
                i += 1
        elif a.startswith("-") and len(a) > 1:
            if a in vf:
                i += 1
            else:
                flags.add(a)
                flags.update("-" + ch for ch in a[1:])
        else:
            pos.append(a)
        i += 1
    return {"name": name, "argv": argv, "args": args, "flags": flags, "pos": pos,
            "redirs": redirs, "downstream": [], "via": list(via)}


def _resolve(argv, redirs, via, depth):
    """Return leaves for one simple command. The first leaf is the command itself."""
    argv = list(argv)
    via = tuple(via)
    while argv:
        if _ASSIGN.match(argv[0]) or argv[0] in _KEYWORDS:
            argv.pop(0)
            continue
        name = os.path.basename(argv[0])
        if name not in WRAPPERS or len(argv) == 1:
            break
        takes = WRAPPERS[name]
        j = 1
        while j < len(argv):
            a = argv[j]
            if a == "--":
                j += 1
                break
            if a.startswith("-") and len(a) > 1:
                j += 2 if a in takes else 1
            elif name == "env" and _ASSIGN.match(a):
                j += 1
            else:
                break
        if name == "timeout" and j < len(argv):
            j += 1
        if j >= len(argv):
            break
        via += (name,)
        argv = argv[j:]
    leaves = [_leaf(argv, redirs, via)]
    if not argv:
        return leaves
    name, args = leaves[0]["name"], argv[1:]
    if name in SHELLS:
        for k, a in enumerate(args):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                script = next((x for x in args[k + 1:] if not x.startswith("-")), None)
                if script is not None:
                    leaves += analyze(script, via + (name + " -c",), depth + 1)
                break
    elif name == "eval" and args:
        leaves += analyze(" ".join(args), via + ("eval",), depth + 1)
    elif name == "find":
        k = 0
        while k < len(args):
            if args[k] in ("-exec", "-execdir", "-ok", "-okdir"):
                end = k + 1
                while end < len(args) and args[end] not in (";", "+"):
                    end += 1
                if end > k + 1:
                    leaves += _resolve(args[k + 1:end], [], via + ("find " + args[k],), depth + 1)
                k = end
            k += 1
    return leaves


def analyze(text, via=(), depth=0):
    """Return every simple command that `text` would run, as a flat list of leaves."""
    if depth > MAX_DEPTH:
        raise ParseError("nesting too deep")
    leaves = []
    for pipe in pipelines(lex(text)):
        members = [_resolve(c["argv"], c["redirs"], via, depth) for c in pipe]
        for k, m in enumerate(members):
            m[0]["downstream"] = [x[0]["name"] for x in members[k + 1:]]
            leaves += m
        for c in pipe:
            for inner in c["subs"]:
                leaves += analyze(inner, tuple(via) + ("$()",), depth + 1)
    return leaves


# ---------------------------------------------------------------- policy

class Policy:
    def __init__(self, rules):
        self.rules = []
        for r in rules:
            if r["action"] not in ("warn", "block"):
                raise ValueError("rule %s: action must be warn or block" % r.get("id"))
            c = dict(r)
            for key in ("pos_re", "args_re", "redir_re", "cmd_re"):
                if key in c:
                    c[key] = re.compile(c[key])
            self.rules.append(c)

    @classmethod
    def load(cls, path=None):
        path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.json")
        with open(path) as f:
            return cls(json.load(f)["rules"])

    @staticmethod
    def _match(r, leaf):
        if "cmd" in r and leaf["name"] not in r["cmd"]:
            return False
        if "cmd_re" in r and not r["cmd_re"].search(leaf["name"]):
            return False
        if "sub" in r and not any(leaf["pos"][:len(alt)] == alt for alt in r["sub"]):
            return False
        for group in r.get("flags", ()):
            if not leaf["flags"].intersection(group):
                return False
        if leaf["flags"].intersection(r.get("not_flags", ())):
            return False
        if "pos_re" in r and not any(r["pos_re"].search(p) for p in leaf["pos"]):
            return False
        if "args_re" in r and not r["args_re"].search(" ".join(leaf["args"])):
            return False
        if "downstream" in r and not set(leaf["downstream"]).intersection(r["downstream"]):
            return False
        if "redir_re" in r and not any(r["redir_re"].search(t) for _, t in leaf["redirs"]):
            return False
        return True

    def check(self, command):
        """Return {"action", "findings", "commands"} for one command string."""
        try:
            leaves = analyze(command)
        except ParseError as e:
            # A command I cannot parse is not one I can call safe.
            return {"action": "warn", "commands": 0, "findings": [
                {"rule": "unparseable", "action": "warn", "why": "could not parse: %s" % e,
                 "command": command, "via": []}]}
        findings = []
        for leaf in leaves:
            for r in self.rules:
                if self._match(r, leaf):
                    findings.append({"rule": r["id"], "action": r["action"], "why": r["why"],
                                     "command": " ".join(leaf["argv"]), "via": leaf["via"]})
        action = max((f["action"] for f in findings), key=LEVEL.get, default="allow")
        return {"action": action, "commands": len(leaves), "findings": findings}


def hook_response(policy, event):
    """Map a PreToolUse hook event to a response dict, or None to stay out of the way."""
    command = (event.get("tool_input") or {}).get("command")
    if not isinstance(command, str):
        return None
    d = policy.check(command)
    if d["action"] == "allow":
        return None  # never auto-approve; the agent's normal permission flow still applies
    top = [f for f in d["findings"] if f["action"] == d["action"]]
    reason = "; ".join("%s: %s [%s]" % (f["rule"], f["why"], f["command"]) for f in top)
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny" if d["action"] == "block" else "ask",
        "permissionDecisionReason": reason}}


def main(argv):
    args = list(argv)
    path = None
    if "--policy" in args:
        k = args.index("--policy")
        path = args[k + 1]
        del args[k:k + 2]
    if len(args) == 2 and args[0] == "check":
        d = Policy.load(path).check(args[1])
        print(json.dumps(d, indent=2))
        return LEVEL[d["action"]]
    if args == ["hook"]:
        resp = hook_response(Policy.load(path), json.load(sys.stdin))
        if resp:
            print(json.dumps(resp))
        return 0
    print("usage: cmdgate.py [--policy FILE] check '<command>' | hook < event.json", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
