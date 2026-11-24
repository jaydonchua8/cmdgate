"""shparse: a small shell lexer and expander for static analysis.

It does not run anything. It splits a command string into words, operators,
redirects and heredoc bodies, and keeps each word as a list of segments so the
caller can expand variables and substitutions with whatever it knows statically.
Standard library only.
"""
import base64
import binascii
import re


class ParseError(ValueError):
    pass


_REDIR = re.compile(r"(?:\d+|&)?(?:>>|>&|>\||<<<|<<-?|<&|<>|>|<)")
_OPS = ("&&", "||", ";;", "|&", ";", "|", "&", "\n", "(", ")")
_NAME = re.compile(r"[A-Za-z_]\w*")
_PARAM = re.compile(r"^([A-Za-z_]\w*)(?:(:?[-=])(.*))?$", re.S)
_SPECIAL = "@*#?$!-0123456789"
_GLOB = re.compile(r"[*?\[]")
_PLAIN = re.compile(r"[^ \t\n\\'\"$`<>;&|()]+")   # a run with nothing special in it
_DQ_PLAIN = re.compile(r'[^"\\$`]+')


class Word:
    """One shell word. segs is a list of:
    ("lit", text, quoted)
    ("var", name_or_None, default_or_None, quoted, raw)
    ("sub", inner, quoted, raw)      $( ) or backticks
    ("psub", inner, raw)             <( ) or >( )
    """
    __slots__ = ("_segs", "_parts", "_quoted")

    def __init__(self):
        self._segs, self._parts, self._quoted = [], [], False

    def lit(self, text, quoted):
        # pieces are joined once, so a long quoted string stays linear to lex
        if self._parts and self._quoted != quoted:
            self._flush()
        self._parts.append(text)
        self._quoted = quoted

    def _flush(self):
        if self._parts:
            self._segs.append(("lit", "".join(self._parts), self._quoted))
            self._parts = []

    @property
    def segs(self):
        self._flush()
        return self._segs

    @property
    def text(self):
        """The word with quotes removed and expansions left as written."""
        return "".join(s[1] if s[0] == "lit" else s[-1] for s in self.segs)

    @property
    def quoted(self):
        return any((s[0] in ("lit", "sub") and s[2]) or (s[0] == "var" and s[3]) for s in self.segs)

    @property
    def subs(self):
        return [s[1] for s in self.segs if s[0] in ("sub", "psub")]


def _read_paren(s, i):
    """s[i:] starts just after an opening '('. Return (inner, index after the matching ')')."""
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


def _read_brace(s, i):
    """s[i:] starts just after '${'. Return (content, index after '}')."""
    depth, start, n = 1, i, len(s)
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return s[start:i], i + 1
        i += 1
    raise ParseError("unterminated ${")


def unescape(text):
    """Decode backslash escapes the way `echo -e`, printf and $'..' do."""
    def rep(m):
        e = m.group(1)
        simple = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "a": "\a",
                  "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v"}
        if e in simple:
            return simple[e]
        if e[0] == "x" and len(e) > 1:
            return chr(int(e[1:], 16))
        return chr(int(e.lstrip("0") or "0", 8) & 0xFF) if e[0] in "01234567" else "\\" + e
    return re.sub(r"\\(x[0-9A-Fa-f]{1,2}|[0-7]{1,4}|.)", rep, text, flags=re.S)


def _dollar(s, i, word, quoted):
    """s[i] == '$'. Append the right segment to word and return the new index."""
    n = len(s)
    nxt = s[i + 1:i + 2]
    if nxt == "(":
        if s[i + 2:i + 3] == "(":  # arithmetic: keep as text
            j = s.find("))", i + 3)
            if j < 0:
                raise ParseError("unterminated $((")
            word.lit(s[i:j + 2], quoted)
            return j + 2
        inner, j = _read_paren(s, i + 2)
        word.segs.append(("sub", inner, quoted, s[i:j]))
        return j
    if nxt == "{":
        content, j = _read_brace(s, i + 2)
        m = _PARAM.match(content)
        if m:
            word.segs.append(("var", m.group(1), m.group(3) if m.group(2) else None, quoted, s[i:j]))
        else:
            word.segs.append(("var", None, None, quoted, s[i:j]))
        return j
    m = _NAME.match(s, i + 1)
    if m:
        word.segs.append(("var", m.group(0), None, quoted, s[i:m.end()]))
        return m.end()
    if nxt and nxt in _SPECIAL:
        word.segs.append(("var", None, None, quoted, s[i:i + 2]))
        return i + 2
    word.lit("$", quoted)
    return i + 1


def lex(s):
    """Return tokens: ("w", text, subs, Word), ("op", text) or ("redir", op, heredoc).

    heredoc is None except for << and <<-, where it is {"body": str, "quoted": bool}.
    """
    toks, cur, pending = [], None, []
    i, n = 0, len(s)

    def flush():
        nonlocal cur
        if cur is not None:
            toks.append(("w", cur.text, cur.subs, cur))
            cur = None

    def word():
        nonlocal cur
        if cur is None:
            cur = Word()
        return cur

    def read_heredocs(i):
        """i is just after a newline. Fill pending heredoc bodies, return the new index."""
        for idx in pending:
            op, hd = toks[idx][1], toks[idx][2]
            delim = toks[idx + 1] if idx + 1 < len(toks) and toks[idx + 1][0] == "w" else None
            if delim is None:
                raise ParseError("heredoc without a delimiter")
            hd["quoted"] = delim[3].quoted
            lines = []
            while i < n:
                j = s.find("\n", i)
                line = s[i:] if j < 0 else s[i:j]
                i = n if j < 0 else j + 1
                if (line.lstrip("\t") if op.endswith("-") else line) == delim[1]:
                    break
                lines.append(line)
            hd["body"] = "\n".join(lines)
        del pending[:]
        return i

    while i < n:
        c = s[i]
        if c == "\\":
            if i + 1 >= n:
                raise ParseError("trailing backslash")
            if s[i + 1] != "\n":
                word().lit(s[i + 1], True)
            i += 2
        elif c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise ParseError("unterminated single quote")
            word().lit(s[i + 1:j], True)
            i = j + 1
        elif c == "$" and s[i + 1:i + 2] == "'":
            j = i + 2
            while j < n and s[j] != "'":
                j += 2 if s[j] == "\\" else 1
            if j >= n:
                raise ParseError("unterminated $' quote")
            word().lit(unescape(s[i + 2:j]), True)
            i = j + 1
        elif c == '"':
            w = word()
            w.lit("", True)
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
                        w.lit(s[i + 1], True)
                    i += 2
                elif d == "$":
                    i = _dollar(s, i, w, True)
                elif d == "`":
                    inner, j = _read_tick(s, i + 1)
                    w.segs.append(("sub", inner, True, s[i:j]))
                    i = j
                else:
                    m = _DQ_PLAIN.match(s, i)
                    if m:
                        w.lit(m.group(0), True)
                        i = m.end()
                    else:  # a backslash that escapes nothing
                        w.lit(d, True)
                        i += 1
        elif c == "$":
            i = _dollar(s, i, word(), False)
        elif c == "`":
            inner, j = _read_tick(s, i + 1)
            word().segs.append(("sub", inner, False, s[i:j]))
            i = j
        elif c in "<>" and s[i + 1:i + 2] == "(" and cur is None:
            inner, j = _read_paren(s, i + 2)
            word().segs.append(("psub", inner, s[i:j]))
            i = j
        elif c in " \t":
            flush()
            i += 1
        elif c == "#" and cur is None:
            j = s.find("\n", i)
            i = n if j < 0 else j
        else:
            m = _REDIR.match(s, i) if (cur is None or c in "<>") else None
            if m:
                flush()
                op = m.group(0)
                hd = {"body": "", "quoted": False} if op.lstrip("0123456789").startswith("<<") \
                    and not op.endswith("<<<") else None
                if hd is not None:
                    pending.append(len(toks))
                toks.append(("redir", op, hd))
                i = m.end()
                continue
            for op in _OPS:
                if s.startswith(op, i):
                    flush()
                    toks.append(("op", op))
                    i += len(op)
                    if op == "\n" and pending:
                        i = read_heredocs(i)
                    break
            else:
                m = _PLAIN.match(s, i)
                word().lit(m.group(0) if m else c, False)
                i = m.end() if m else i + 1
    flush()
    if pending:
        read_heredocs(n)
    return toks


def pipelines(tokens):
    """Group tokens into pipelines. Each command is {"words": [Word], "redirs": [(op, Word, heredoc)]}.

    Also returns the number of && || ; separators, which the policy can limit.
    """
    out, pipe, seps = [], [], 0
    cmd = {"words": [], "redirs": []}
    pending = None

    def end_cmd():
        nonlocal cmd
        if cmd["words"] or cmd["redirs"]:
            pipe.append(cmd)
        cmd = {"words": [], "redirs": []}

    for t in tokens:
        if t[0] == "w":
            if pending is not None:
                cmd["redirs"].append((pending[1], t[3], pending[2]))
                pending = None
            else:
                cmd["words"].append(t[3])
        elif t[0] == "redir":
            pending = t
        else:
            pending = None
            end_cmd()
            if t[1] in ("&&", "||", ";"):
                seps += 1
            if t[1] not in ("|", "|&"):
                if pipe:
                    out.append(pipe)
                pipe = []
    end_cmd()
    if pipe:
        out.append(pipe)
    return out, seps


# ---------------------------------------------------------------- expansion

def _brace(text):
    m = re.match(r"^(.*?)\{([^{}]*,[^{}]*)\}(.*)$", text, re.S)
    if not m:
        return [text]
    out = []
    for alt in m.group(2).split(","):
        out.extend(_brace(m.group(1) + alt + m.group(3)))
    return out


def expand(word, env, eval_sub=None):
    """Expand one Word to a list of fields using statically known values.

    env maps names to strings, or to None when the value is only known at run time.
    Returns (fields, info); info has dyn (something was left unresolved), glob (an
    unquoted glob character in the first field) and notes (what was resolved).
    """
    fields, info = [""], {"dyn": False, "glob": False, "notes": []}
    plain = True

    def add(value, split):
        if not split:
            fields[-1] += value
            return
        parts = re.split(r"[ \t\n]+", value)
        fields[-1] += parts[0]
        for p in parts[1:]:
            fields.append(p)

    for seg in word.segs:
        kind = seg[0]
        if kind == "lit":
            if seg[2]:
                plain = False
            elif len(fields) == 1 and _GLOB.search(seg[1]):
                info["glob"] = True
            fields[-1] += seg[1]
            continue
        plain = False
        value = None
        if kind == "var":
            name, default = seg[1], seg[2]
            if name is not None and name in env:
                value = env[name]
            elif name == "IFS":
                value = " "
            elif default is not None:
                value = default
            if value is not None:
                info["notes"].append("%s -> %r" % (seg[4], value))
        elif kind == "sub" and eval_sub is not None:
            value = eval_sub(seg[1])
            if value is not None:
                value = value.rstrip("\n")
                info["notes"].append("%s -> %r" % (seg[3], value))
        if value is None:
            info["dyn"] = True
            fields[-1] += seg[-1]
        else:
            add(value, not (seg[3] if kind == "var" else seg[2]))
    if not word.quoted:
        fields = [f for f in fields if f != ""]
    if plain and len(fields) == 1:
        fields = _brace(fields[0])
        if len(fields) > 1:
            info["notes"].append("brace expansion -> %r" % " ".join(fields))
    return fields, info


# ---------------------------------------------------------------- static output of simple producers

def echo_output(name, args):
    """What `echo` or `printf` would print for literal arguments, or None."""
    if name == "echo":
        interpret, newline = False, True
        while args and re.match(r"^-[neE]+$", args[0]):
            interpret = interpret or "e" in args[0]
            newline = newline and "n" not in args[0]
            args = args[1:]
        text = " ".join(args)
        return (unescape(text) if interpret else text) + ("\n" if newline else "")
    if name == "printf":
        if args and args[0] == "--":
            args = args[1:]
        if not args:
            return None
        fmt, rest = unescape(args[0]), list(args[1:])

        def once():
            def rep(m):
                if m.group(0) == "%%":
                    return "%"
                v = rest.pop(0) if rest else ""
                return unescape(v) if m.group(0) == "%b" else v
            return re.sub(r"%%|%[-0-9.]*[sbdq]", rep, fmt)
        out = once()
        while rest:
            left = len(rest)
            more = once()
            if len(rest) == left:
                break
            out += more
        return out
    return None


def transform(name, flags, pos, text):
    """Output of a known pure filter given static input text, or None."""
    if name == "base64" and flags & {"-d", "-D", "--decode"}:
        try:
            return base64.b64decode(re.sub(r"\s+", "", text), validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return None
    if name == "xxd" and "-r" in flags and "-p" in flags:
        try:
            return bytes.fromhex(re.sub(r"\s+", "", text)).decode("utf-8", "replace")
        except ValueError:
            return None
    if name == "rev" and not pos:
        return "\n".join(line[::-1] for line in text.split("\n"))
    if name in ("cat", "tee") and not flags:
        return text if (name == "tee" or not pos) else None
    return None
