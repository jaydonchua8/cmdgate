"""resolve: work out which simple commands a shell command string would really run.

The Analyzer walks pipelines in order and keeps the little state it can know
statically: variables and aliases assigned earlier in the same string, files
written by echo/printf/heredoc earlier in the same string, and text flowing
through a pipe from a literal producer. It follows wrappers (sudo, env, xargs),
`sh -c`, eval, substitutions, heredocs fed to a shell, `echo .. | base64 -d | sh`,
ssh, `docker exec`, `find -exec`, inline `python -c` / `node -e` code that shells
out, and, when given a working directory, script files and package.json scripts
on disk. Nothing is executed.
"""
import json
import os
import re

from shparse import ParseError, lex, pipelines, expand, echo_output, transform, unescape

MAX_DEPTH = 8
MAX_COMMANDS = 2000
MAX_FILE = 262144

_ASSIGN = re.compile(r"^[A-Za-z_]\w*\+?=")
_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "fi", "done", "time"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
# wrapper -> options that take a value
WRAPPERS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"}, "doas": {"-u", "-C"},
    "env": {"-u", "-C"}, "nohup": set(), "command": set(), "exec": {"-a"},
    "builtin": set(), "nice": {"-n"}, "ionice": {"-c", "-n", "-p"}, "timeout": {"-s", "-k"},
    "stdbuf": {"-i", "-o", "-e"}, "xargs": {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"},
    "busybox": set(), "setsid": set(), "watch": {"-n"}, "npx": {"-p", "--package"}, "bunx": set(),
    "caffeinate": set(), "chronic": set(), "unbuffer": set(),
}
# command -> options whose next argument is a value, so it is not a positional
VALUE_FLAGS = {
    "git": {"-C", "-c"},
    "kubectl": {"-n", "--namespace", "--context", "--kubeconfig", "-l", "--selector"},
    "psql": {"-h", "-U", "-d", "-p"},
    "mysql": {"-h", "-u", "-P", "-D"},
    "aws": {"--profile", "--region", "--endpoint-url"},
    "docker": {"-H", "--context"},
    "terraform": set(), "tofu": set(),
}
_SSH_VALUE = set("-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w".split())
_DOCKER_EXEC_VALUE = {"-u", "--user", "-w", "--workdir", "-e", "--env", "--env-file", "--detach-keys"}
_INTERP = re.compile(r"^(python[\d.]*|node|nodejs|perl|ruby|php|bun|deno)$")
_CODE_FLAGS = {"python": {"-c"}, "node": {"-e", "--eval", "-p", "--print"}, "nodejs": {"-e", "--eval", "-p"},
               "perl": {"-e", "-E"}, "ruby": {"-e"}, "php": {"-r"}, "bun": {"-e", "--eval"}, "deno": set()}
_SHELL_OUT = re.compile(
    r"os\.system|os\.popen|subprocess\.|\bsystem\s*\(|\bexec(Sync|File|FileSync)?\s*\(|\bspawn(Sync)?\s*\("
    r"|child_process|\bpopen\b|shell_exec|passthru|proc_open|`|%x[\[({]|\bqx\b|\bsystem\s+[\"']|\bexec\s+[\"']")
_FILE_DELETE = re.compile(
    r"shutil\.rmtree|\brmtree\b|\brmSync\b|\brmdirSync\b|fs\.rm\s*\(|fs\.rmdir\s*\(|rm_rf|rm_r\b|remove_tree|removedirs")
_STR = re.compile(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"")
_SHEBANG = re.compile(r"^#!.*\b(sh|bash|zsh|dash|ksh)\b")
_NPM_BUILTIN = {"test", "start", "stop", "restart"}


def make_leaf(argv, redirs, via):
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
            "redirs": redirs, "downstream": [], "upstream": [], "via": list(via),
            "dyn_name": False, "glob_name": False, "dyn_args": False, "procsubs": [], "notes": []}


class Analyzer:
    def __init__(self, cwd=None, follow_files=False):
        self.env, self.aliases, self.files = {}, {}, {}
        self.cwd = cwd
        self.follow = bool(follow_files and cwd)
        self.separators = 0
        self.count = 0
        self.followed = []  # files read from disk, for the audit trail

    # ------------------------------------------------------------ entry points

    def analyze(self, text, via=(), depth=0):
        """Return every simple command that `text` would run, as a flat list of leaves."""
        if depth > MAX_DEPTH:
            raise ParseError("nesting too deep")
        pipes, seps = pipelines(lex(text))
        if depth == 0:
            self.separators = seps
        leaves = []
        for pipe in pipes:
            members, subs, flow = [], [], None
            for c in pipe:
                m, flow, s = self._command(c, tuple(via), depth, flow)
                members.append(m)
                subs += s
            names = [m[0]["name"] for m in members]
            for k, m in enumerate(members):
                m[0]["downstream"] = names[k + 1:]
                m[0]["upstream"] = names[:k]
                leaves += m
            for inner, tag in subs:
                leaves += self.analyze(inner, tuple(via) + (tag,), depth + 1)
        return leaves

    # ------------------------------------------------------------ one command

    def _eval_sub(self, depth):
        def ev(inner):
            if depth >= MAX_DEPTH:
                return None
            try:
                pipes, _ = pipelines(lex(inner))
            except ParseError:
                return None
            if len(pipes) != 1:
                return None
            text = None
            for c in pipes[0]:
                if c["redirs"]:
                    return None
                argv = []
                for w in c["words"]:
                    f, info = expand(w, self.env, None)
                    if info["dyn"]:
                        return None
                    argv += f
                if not argv:
                    return None
                name = os.path.basename(argv[0])
                if text is None:
                    text = echo_output(name, argv[1:])
                else:
                    leaf = make_leaf(argv, [], ())
                    text = transform(name, leaf["flags"], leaf["pos"], text)
                if text is None:
                    return None
            return text
        return ev

    def _command(self, c, via, depth, flow):
        self.count += 1
        if self.count > MAX_COMMANDS:  # bound the work a nested or repeated script can cause
            raise ParseError("too many commands")
        ev = self._eval_sub(depth)
        subs = []
        for w in c["words"] + [r[1] for r in c["redirs"]]:
            subs += [(s[1], "$()" if s[0] == "sub" else "<()") for s in w.segs if s[0] in ("sub", "psub")]
        procsubs = [s[1] for w in c["words"] for s in w.segs if s[0] == "psub"]

        argv, notes, head, dyn_args = [], [], None, False
        assigns, only_assign = [], True
        for w in c["words"]:
            fields, info = expand(w, self.env, ev)
            notes += info["notes"]
            first = w.segs[0] if w.segs else None
            if only_assign and len(w.segs) == 1 and first[0] == "lit" and not first[2] and first[1] in _KEYWORDS:
                continue  # `{ X=1; ...` and `then X=1`: the keyword does not make X=1 an argument
            if only_assign and first and first[0] == "lit" and not first[2] and _ASSIGN.match(first[1]):
                name, value = " ".join(fields).split("=", 1)
                assigns.append((name.rstrip("+"), None if info["dyn"] else value))
                continue
            only_assign = False
            if not argv and fields:
                head = info
            dyn_args = dyn_args or info["dyn"]
            argv += fields
        if not argv:
            for name, value in assigns:  # a bare assignment changes later expansions
                self.env[name] = value
        redirs, stdin, stdin_tag = [], flow, "|"
        for op, w, hd in c["redirs"]:
            fields, info = expand(w, self.env, ev)
            target = " ".join(fields)
            redirs.append((op, target))
            if hd is not None:
                stdin, stdin_tag = hd["body"], "<<"
            elif op.endswith("<<<"):
                stdin, stdin_tag = target + "\n", "<<<"
        meta = {"dyn_args": dyn_args, "notes": notes, "stdin": stdin, "stdin_tag": stdin_tag,
                "procsubs": procsubs}
        if head is not None and argv:
            base = os.path.basename(argv[0])
            meta["dyn_name"] = bool(head["dyn"] and re.search(r"[$`]", base))
            meta["glob_name"] = bool(head["glob"] and re.search(r"[*?\[]", base) and base not in ("[", "[["))
        leaves, out = self._resolve(argv, redirs, via, depth, meta)
        return leaves, out, subs

    def _split(self, text):
        try:
            return [f for t in lex(text) if t[0] == "w" for f in expand(t[3], self.env)[0]]
        except ParseError:
            return text.split()

    def _resolve(self, argv, redirs, via, depth, meta=None):
        """Return (leaves, static stdout or None). The first leaf is the command itself."""
        meta = meta or {}
        argv = list(argv)
        via = tuple(via)
        hops = 0
        while argv:
            if _ASSIGN.match(argv[0]) or argv[0] in _KEYWORDS:
                argv.pop(0)
                continue
            name = os.path.basename(argv[0])
            if name in self.aliases and hops < 4:
                hops += 1
                argv = self._split(self.aliases[name]) + argv[1:]
                via += ("alias " + name,)
                continue
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
        leaf = make_leaf(argv, redirs, via)
        for key in ("dyn_name", "glob_name", "dyn_args", "procsubs", "notes"):
            if key in meta:
                leaf[key] = meta[key]
        leaves = [leaf]
        if not argv:
            return leaves, None
        name, args, d = leaf["name"], argv[1:], depth + 1
        stdin = meta.get("stdin")

        if name in ("alias",):
            for a in args:
                if "=" in a:
                    k, v = a.split("=", 1)
                    self.aliases[k] = v
        elif name in ("export", "declare", "local", "readonly", "typeset"):
            for a in args:
                if _ASSIGN.match(a):
                    k, v = a.split("=", 1)
                    self.env[k] = None if leaf["dyn_args"] else v
        elif name == "read":
            for a in leaf["pos"]:
                self.env[a] = None
        elif name in SHELLS:
            script = None
            for k, a in enumerate(args):
                if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                    script = next((x for x in args[k + 1:] if not x.startswith("-")), None)
                    break
            if script is not None:
                leaves += self.analyze(script, via + (name + " -c",), d)
            elif leaf["pos"]:
                body = self._script(leaf["pos"][0])
                if body is not None:
                    leaves += self.analyze(body, via + ("%s %s" % (name, leaf["pos"][0]),), d)
            elif stdin is not None:
                leaves += self.analyze(stdin, via + ("%s %s" % (meta.get("stdin_tag", "|"), name),), d)
        elif name == "eval":
            leaves += self.analyze(" ".join(args), via + ("eval",), d)
        elif name == "trap" and len(leaf["pos"]) > 1 and leaf["pos"][0] not in ("", "-"):
            leaves += self.analyze(leaf["pos"][0], via + ("trap",), d)
        elif name in ("source", ".") and args:
            body = self._script(args[0])
            if body is not None:
                leaves += self.analyze(body, via + ("source " + args[0],), d)
        elif name == "find":
            k = 0
            while k < len(args):
                if args[k] in ("-exec", "-execdir", "-ok", "-okdir"):
                    end = k + 1
                    while end < len(args) and args[end] not in (";", "+"):
                        end += 1
                    if end > k + 1:
                        leaves += self._resolve(args[k + 1:end], [], via + ("find " + args[k],), d)[0]
                    k = end
                k += 1
        elif name == "ssh":
            k = 0
            while k < len(args) and args[k].startswith("-"):
                k += 2 if args[k] in _SSH_VALUE else 1
            if len(args) > k + 1:
                leaves += self.analyze(" ".join(args[k + 1:]), via + ("ssh",), d)
        elif name in ("docker", "podman") and leaf["pos"][:1] == ["exec"]:
            k = args.index("exec") + 1
            while k < len(args) and args[k].startswith("-"):
                k += 2 if args[k] in _DOCKER_EXEC_VALUE else 1
            if len(args) > k + 1:
                leaves += self._resolve(args[k + 1:], [], via + (name + " exec",), d)[0]
        elif name == "kubectl" and leaf["pos"][:1] == ["exec"] and "--" in args:
            rest = args[args.index("--") + 1:]
            if rest:
                leaves += self._resolve(rest, [], via + ("kubectl exec",), d)[0]
        elif _INTERP.match(name):
            lang = re.sub(r"[\d.]+$", "", name)
            for k, a in enumerate(args):
                if a in _CODE_FLAGS.get(lang, ()) and k + 1 < len(args):
                    leaves += self._inline(args[k + 1], lang + " " + a, via, d)
                    break
        elif name in ("npm", "pnpm", "yarn", "bun") and self.follow:
            leaves += self._package_script(name, leaf["pos"], via, d)
        elif "/" in argv[0]:
            body = self._script(argv[0], need_shell=True)
            if body is not None:
                leaves += self.analyze(body, via + ("script " + argv[0],), d)

        # static stdout, so a later `| sh` or `sh file` can be analysed
        out = None
        if not leaf["dyn_args"]:
            if name in ("echo", "printf"):
                out = echo_output(name, args)
            elif stdin is not None:
                out = transform(name, leaf["flags"], leaf["pos"], stdin)
        if name == "tee" and stdin is not None:
            for p in leaf["pos"]:
                self._write(p, stdin, "-a" in leaf["flags"])
        for op, target in redirs:
            core = op.lstrip("0123456789&")
            if core in (">", ">>", ">|") and op[:len(op) - len(core)] in ("", "1", "&"):
                if out is not None:
                    self._write(target, out, core == ">>")
                out = None
        return leaves, out

    # ------------------------------------------------------------ files

    def _write(self, path, text, append):
        key = os.path.normpath(path)
        self.files[key] = (self.files.get(key, "") if append else "") + text

    def _script(self, path, need_shell=False):
        """Content of a script the command would run: written earlier in this command, or on disk."""
        key = os.path.normpath(path)
        if key in self.files:
            return self.files[key]
        if not self.follow:
            return None
        full = os.path.join(self.cwd, os.path.expanduser(path))
        try:
            if not os.path.isfile(full) or os.path.getsize(full) > MAX_FILE:
                return None
            with open(full, "rb") as f:
                data = f.read(MAX_FILE)
        except OSError:
            return None
        if b"\0" in data[:2048]:
            return None
        text = data.decode("utf-8", "replace")
        if need_shell and not (key.endswith((".sh", ".bash", ".zsh", ".ksh")) or _SHEBANG.match(text)):
            return None
        self.followed.append(full)
        return text

    def _package_script(self, name, pos, via, depth):
        if pos[:1] in (["run"], ["run-script"]) and len(pos) > 1:
            script = pos[1]
        elif pos and (name != "npm" or pos[0] in _NPM_BUILTIN):
            script = pos[0]
        else:
            return []
        full = os.path.join(self.cwd, "package.json")
        try:
            if os.path.getsize(full) > MAX_FILE:
                return []
            with open(full, encoding="utf-8") as f:
                scripts = json.load(f).get("scripts", {})
        except (OSError, ValueError, AttributeError):
            return []
        body = scripts.get(script) if isinstance(scripts, dict) else None
        if not isinstance(body, str):
            return []
        self.followed.append(full)
        return self.analyze(body, via + ("%s run %s" % (name, script),), depth)

    # ------------------------------------------------------------ inline interpreter code

    def _inline(self, code, tag, via, depth):
        """Heuristic: if inline code shells out or deletes trees, analyse its string literals."""
        leaves = []
        strings = [unescape(a or b) for a, b in _STR.findall(code)]
        if _SHELL_OUT.search(code):
            for lst in re.findall(r"\[([^\[\]]*)\]", code):
                items = [a or b for a, b in _STR.findall(lst)]
                if items and not _STR.sub("", lst).strip(" ,\n\t"):
                    leaves += self._resolve(items, [], via + (tag,), depth)[0]
            for s in strings + re.findall(r"`([^`]+)`", code):
                if " " in s.strip():
                    try:
                        leaves += self.analyze(s, via + (tag,), depth)
                    except ParseError:
                        pass
        if _FILE_DELETE.search(code):
            paths = [s for s in strings if s and (s[0] in "/~." or "/" in s) and " " not in s]
            for p in paths or ["<computed>"]:
                leaves.append(make_leaf(["rm", "-rf", p], [], via + (tag + " file API",)))
        return leaves


def analyze(text, via=(), depth=0, cwd=None, follow_files=False):
    return Analyzer(cwd, follow_files).analyze(text, via, depth)
