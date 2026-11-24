"""cmdgate: decide what to do with a shell command an AI coding agent wants to run.

The command is parsed into the simple commands that would actually execute (see
resolve.py) and each one is checked against structured rules in policy.json.
Every rule carries a risk level (low, medium, high, critical). A tier turns the
highest risk into an action: allow, warn, ask or block. The risk levels, tier
names and the tier matrix follow the ones published in Unbound's open OACB
baseline, so a decision here can be compared with that hook case by case.
Standard library only.
"""
import json
import os
import re
import sys
from urllib.parse import urlsplit

from shparse import ParseError, lex  # noqa: F401  (lex is re-exported)
from resolve import Analyzer, analyze  # noqa: F401

LEVEL = {"allow": 0, "warn": 1, "block": 2}
RISK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# tier -> risk -> action. Same matrix as _tier_action in OACB's oacb-enforce-core.sh.
TIERS = {
    "shadow": {"low": "allow", "medium": "allow", "high": "allow", "critical": "allow"},
    "receipts": {"low": "allow", "medium": "warn", "high": "warn", "critical": "warn"},
    "baseline": {"low": "allow", "medium": "allow", "high": "ask", "critical": "block"},
    "strict": {"low": "allow", "medium": "warn", "high": "block", "critical": "block"},
    "paranoid": {"low": "allow", "medium": "block", "high": "block", "critical": "block"},
}
UNPARSEABLE_RISK = "high"
MAX_INPUT_BYTES = 131072

_MATCH_KEYS = {"cmd", "cmd_re", "sub", "flags", "not_flags", "pos_re", "pos_from", "first_pos_re", "args_re", "argv_re",
               "downstream", "upstream", "redir_re", "via_any", "dyn_name", "glob_name", "dyn_args",
               "procsub_cmd", "untrusted_url", "min_separators"}
_REGEX_KEYS = ("cmd_re", "pos_re", "first_pos_re", "args_re", "argv_re", "redir_re")
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


def _legacy(risk):
    return "block" if risk == "critical" else "allow" if risk == "low" else "warn"


class Policy:
    def __init__(self, rules):
        self.rules = []
        seen = set()
        for r in rules:
            rid = r.get("id")
            if not rid or rid in seen:
                raise ValueError("rule id missing or repeated: %r" % rid)
            seen.add(rid)
            c = dict(r)
            if "risk" not in c:  # first-version rules only had an action
                if c.get("action") not in ("warn", "block"):
                    raise ValueError("rule %s: needs a risk, or an action of warn or block" % rid)
                c["risk"] = "critical" if c["action"] == "block" else "high"
            if c["risk"] not in RISK:
                raise ValueError("rule %s: unknown risk %r" % (rid, c["risk"]))
            unknown = set(c) - _MATCH_KEYS - {"id", "why", "risk", "action", "oacb"}
            if unknown:
                raise ValueError("rule %s: unknown keys %s" % (rid, sorted(unknown)))
            if not set(c) & (_MATCH_KEYS - {"pos_from"}):
                raise ValueError("rule %s: matches every command" % rid)
            for key in _REGEX_KEYS:
                if key in c:
                    try:
                        c[key] = re.compile(c[key])
                    except re.error as e:
                        raise ValueError("rule %s: bad %s: %s" % (rid, key, e))
            c.setdefault("why", rid)
            self.rules.append(c)

    @classmethod
    def load(cls, path=None):
        path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.json")
        with open(path) as f:
            return cls(json.load(f)["rules"])

    @staticmethod
    def _untrusted(leaf, trusted):
        hosts = [urlsplit(a).hostname or "" for a in leaf["args"] if _URL.match(a)]
        return not hosts or any(h.lower() not in trusted for h in hosts)

    @classmethod
    def _match(cls, r, leaf):
        if "min_separators" in r:
            return False  # checked once per command, not per leaf
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
        if "pos_re" in r and not any(r["pos_re"].search(p) for p in leaf["pos"][r.get("pos_from", 0):]):
            return False
        if "first_pos_re" in r and not (leaf["pos"] and r["first_pos_re"].search(leaf["pos"][0])):
            return False
        if "args_re" in r and not r["args_re"].search(" ".join(leaf["args"])):
            return False
        if "argv_re" in r and not r["argv_re"].search(" ".join(leaf["argv"])):
            return False
        if "downstream" in r and not set(leaf["downstream"]).intersection(r["downstream"]):
            return False
        if "upstream" in r and not set(leaf["upstream"]).intersection(r["upstream"]):
            return False
        if "redir_re" in r and not any(r["redir_re"].search(t) for _, t in leaf["redirs"]):
            return False
        if "via_any" in r and not set(leaf["via"]).intersection(r["via_any"]):
            return False
        for key in ("dyn_name", "glob_name", "dyn_args"):
            if key in r and bool(leaf[key]) != bool(r[key]):
                return False
        if "procsub_cmd" in r and not any(
                re.match(r"\s*(\S*/)?(%s)\b" % "|".join(map(re.escape, r["procsub_cmd"])), p)
                for p in leaf["procsubs"]):
            return False
        if "untrusted_url" in r and not cls._untrusted(leaf, r["untrusted_url"]):
            return False
        return True

    def _finding(self, r, command, via=(), notes=()):
        f = {"rule": r["id"], "risk": r["risk"], "action": _legacy(r["risk"]), "why": r["why"],
             "command": command, "via": list(via)}
        if r.get("oacb"):
            f["oacb"] = r["oacb"]
        if notes:
            f["resolved"] = list(notes)
        return f

    def check(self, command, cwd=None, follow_files=False):
        """Return {"action", "risk", "commands", "findings"} for one command string.

        action is the tier-free summary: block for critical, warn for medium or high.
        Use decide() to turn the result into a per-tier action.
        """
        an = Analyzer(cwd, follow_files)
        try:
            leaves = an.analyze(command)
        except (ParseError, RecursionError) as e:
            # A command I cannot parse is not one I can call safe.
            return {"action": "warn", "risk": UNPARSEABLE_RISK, "commands": 0, "findings": [
                {"rule": "unparseable", "risk": UNPARSEABLE_RISK, "action": "warn",
                 "why": "could not parse: %s" % e, "command": command, "via": []}]}
        findings = []
        for leaf in leaves:
            for r in self.rules:
                if self._match(r, leaf):
                    findings.append(self._finding(r, " ".join(leaf["argv"]), leaf["via"], leaf["notes"]))
        for r in self.rules:
            if "min_separators" in r and an.separators >= r["min_separators"]:
                f = self._finding(r, command[:200])
                f["why"] = "%s (%d separators)" % (r["why"], an.separators)
                findings.append(f)
        risk = max((f["risk"] for f in findings), key=RISK.get, default="low")
        out = {"action": _legacy(risk) if findings else "allow", "risk": risk if findings else "low",
               "commands": len(leaves), "findings": findings}
        if an.followed:
            out["files_read"] = an.followed
        return out


def decide(result, tier="baseline", prod=False):
    """Turn a check() result into allow / warn / ask / block for a tier.

    prod mirrors OACB's promote-on-context: in a production context high becomes critical.
    """
    if tier not in TIERS:
        raise ValueError("unknown tier %r" % tier)
    risk = result["risk"]
    if prod and risk == "high":
        risk = "critical"
    if not result["findings"]:
        return "allow", "low"
    return TIERS[tier][risk], risk


def top_findings(result):
    return [f for f in result["findings"] if f["risk"] == max(
        (g["risk"] for g in result["findings"]), key=RISK.get)]


def reason_text(result):
    return "; ".join("%s: %s [%s]" % (f["rule"], f["why"], f["command"]) for f in top_findings(result))


def _deny(reason, decision="deny"):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": reason}}


def hook_response(policy, event, tier="baseline", follow_files=False):
    """Map a PreToolUse hook event to a response dict, or None to stay out of the way."""
    if not isinstance(event, dict):
        return _deny("cmdgate: hook input was not a JSON object")
    command = (event.get("tool_input") or {}).get("command") if isinstance(event.get("tool_input"), dict) else None
    if event.get("tool_name") not in (None, "Bash") or not isinstance(command, str):
        return None
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else None
    d = policy.check(command, cwd, follow_files)
    action, _ = decide(d, tier)
    if action in ("allow", "warn"):
        return None  # never auto-approve; the agent's normal permission flow still applies
    return _deny(reason_text(d), "deny" if action == "block" else "ask")


def hook_main(policy, raw, tier="baseline", follow_files=False):
    """Hook entry point that fails closed: bad input becomes a deny, not a crash."""
    if len(raw.encode("utf-8", "replace")) > MAX_INPUT_BYTES:
        return _deny("cmdgate: hook input larger than %d bytes" % MAX_INPUT_BYTES)
    try:
        event = json.loads(raw)
    except ValueError:
        return _deny("cmdgate: hook input was not valid JSON")
    try:
        return hook_response(policy, event, tier, follow_files)
    except Exception as e:  # a bug in the checker must not turn into a silent allow
        return _deny("cmdgate: internal error (%s); blocked to be safe" % type(e).__name__)


def _take(args, flag, default=None):
    if flag in args:
        k = args.index(flag)
        if k + 1 >= len(args):
            raise SystemExit("%s needs a value" % flag)
        value = args[k + 1]
        del args[k:k + 2]
        return value
    return default


USAGE = ("usage: cmdgate.py [--policy FILE] [--tier TIER] [--cwd DIR] check '<command>'\n"
         "       cmdgate.py [--policy FILE] [--tier TIER] [--no-follow] hook < event.json")


def main(argv):
    args = list(argv)
    path = _take(args, "--policy")
    tier = _take(args, "--tier", "baseline")
    cwd = _take(args, "--cwd")
    follow = "--no-follow" not in args
    args = [a for a in args if a != "--no-follow"]
    if tier not in TIERS:
        print("unknown tier %r (choose from %s)" % (tier, ", ".join(TIERS)), file=sys.stderr)
        return 64
    if len(args) == 2 and args[0] == "check":
        d = Policy.load(path).check(args[1], cwd, follow_files=cwd is not None)
        d["tier"], d["decision"] = tier, decide(d, tier)[0]
        print(json.dumps(d, indent=2))
        return LEVEL[d["action"]]
    if args == ["hook"]:
        try:
            policy = Policy.load(path)
        except (OSError, ValueError, KeyError) as e:
            print(json.dumps(_deny("cmdgate: policy could not be loaded (%s)" % e)))
            return 0
        resp = hook_main(policy, sys.stdin.read(), tier, follow)
        if resp:
            print(json.dumps(resp))
        return 0
    print(USAGE, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
