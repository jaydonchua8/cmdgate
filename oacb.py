"""oacb: run cmdgate under the hook contract of Unbound's open OACB baseline.

OACB (github.com/websentry-ai/oacb) ships a Bash PreToolUse hook that matches
regexes against the command string, and a conformance suite whose cases live in
conformance-tests/expected.json. This module does three things:

  hook      read the same stdin JSON, exit 0 or 2 the same way, print the rule on
            stderr, and write one audit line per decision with the same keys
  conform   load expected.json from an OACB checkout and report, case by case,
            where cmdgate agrees and disagrees with the expected outcome
  fp        run OACB's false-positive corpus (legitimate-commands.md)

Nothing from OACB is copied into this repo. Point the commands at your own clone.
This is an independent compatibility layer, not part of OACB.
"""
import json
import os
import re
import sys
import time

from cmdgate import Policy, decide, top_findings, TIERS, MAX_INPUT_BYTES

SCHEMA_VERSION = "0.2.1"   # OACB release whose hook contract and audit keys this follows
RUNNER_TIERS = ("baseline", "strict", "paranoid", "receipts")  # same order as conformance-runner.sh


def _compact(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def audit_line(decision, tier, rule, risk, reason, cmd=None, extra=None):
    """One audit entry with the keys OACB documents in oacb-enforce-core.sh, plus evidence."""
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "decision": decision, "tier": tier,
             "rule": rule, "risk": risk, "risk_taxonomy_version": "1.0", "reason": reason}
    if cmd:
        entry["cmd"] = cmd[:500]
    entry["oacb_version"] = SCHEMA_VERSION
    entry["engine"] = "cmdgate"
    if extra:
        entry.update(extra)
    return _compact(entry)


def is_prod_context(env, cwd=None):
    """OACB promote-on-context: a .oacb-context.json with env prod raises high to critical."""
    path = env.get("OACB_CONTEXT_FILE") or os.path.join(cwd or ".", ".oacb-context.json")
    try:
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > 65536:
            return False
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("env") in ("prod", "production")


def run_hook(raw, tier="baseline", env=None, policy=None, follow_files=True):
    """Return (exit_code, stdout, stderr, audit_lines) for one hook invocation.

    Fails closed like the OACB hook: empty, oversized or unparseable input is a block.
    """
    env = env if env is not None else {}
    audit = []

    def block(reason, rule, risk="critical", cmd=None, extra=None, decision="deny"):
        audit.append(audit_line(decision, tier, rule, risk, reason, cmd, extra))
        tag = rule if not (extra or {}).get("oacb_rule") else "%s / %s" % (rule, extra["oacb_rule"])
        out = _compact({"reason": "cmdgate [%s] policy block (%s tier): %s. This is a policy decision, "
                                  "not a transient error. Do not retry with a reworded command."
                                  % (tag, tier, reason)})
        return 2, out, "cmdgate %s [%s]: %s" % (tier, tag, reason), audit

    if tier not in TIERS:
        return block("unknown tier %r" % tier, "cmdgate-env-001")
    if not raw.strip():
        return block("empty stdin to hook", "cmdgate-io-001")
    if len(raw.encode("utf-8", "replace")) > MAX_INPUT_BYTES:
        return block("hook input exceeds %d bytes" % MAX_INPUT_BYTES, "cmdgate-io-004")
    try:
        event = json.loads(raw)
    except ValueError:
        event = None
    tool = event.get("tool_name") if isinstance(event, dict) else None
    if not isinstance(tool, str) or not tool:
        return block("could not parse tool_name from hook input", "cmdgate-io-002")
    if tool != "Bash":
        if tier == "paranoid":
            return block("paranoid tier: tool %r is not handled by this hook" % tool,
                         "cmdgate-paranoid-001", "medium", extra={"oacb_rule": "OACB-PARANOID-001"})
        return 0, "", "", audit
    ti = event.get("tool_input")
    cmd = ti.get("command") if isinstance(ti, dict) else ti
    if not isinstance(cmd, str) or not cmd:
        return block("could not parse tool_input.command from hook input", "cmdgate-io-003")
    cmd = cmd.replace("\r", "").replace("\0", "")
    if tier == "shadow":
        audit.append(audit_line("allow", tier, "shadow", "low", "shadow tier: logged, not enforced", cmd[:200]))
        return 0, "", "", audit

    policy = policy or Policy.load()
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else None
    try:
        result = policy.check(cmd, cwd, follow_files and cwd is not None)
    except Exception as e:  # a checker bug must not become a silent allow
        return block("internal error (%s)" % type(e).__name__, "cmdgate-internal-001", cmd=cmd)
    if not result["findings"]:
        audit.append(audit_line("allow", tier, "default-allow", "low", "no rule matched", cmd))
        return 0, "", "", audit

    action, risk = decide(result, tier, is_prod_context(env, cwd))
    f = top_findings(result)[0]
    extra = {"evidence": {"command": f["command"], "via": f["via"]}}
    if f.get("oacb"):
        extra["oacb_rule"] = f["oacb"]
    if f.get("resolved"):
        extra["evidence"]["resolved"] = f["resolved"]
    if result.get("files_read"):
        extra["evidence"]["files_read"] = result["files_read"]
    reason = "%s [%s]" % (f["why"], f["command"][:160])
    if action == "block":
        return block(reason, f["rule"], risk, cmd, extra)
    if action == "ask":
        # OACB prompts on /dev/tty and blocks after 30s. This hook never prompts, so ask is a block.
        return block("needs human approval: " + reason, f["rule"], risk, cmd, extra, decision="ask")
    if action == "warn":
        audit.append(audit_line("warn", tier, f["rule"], risk, reason, cmd, extra))
        out = _compact({"decision": "approve", "reason": "cmdgate [%s] warning (%s tier): %s. Command allowed."
                                                          % (f["rule"], tier, reason)})
        return 0, out, "", audit
    audit.append(audit_line("allow", tier, f["rule"], risk, "allow: " + reason, cmd, extra))
    return 0, "", "", audit


# ---------------------------------------------------------------- conformance against an OACB checkout

def load_cases(oacb_dir, agent="claude-code"):
    """Yield (case, tier, spec, env) for every enforce-hook check the OACB runner would run."""
    tests = os.path.join(oacb_dir, "conformance-tests")
    with open(os.path.join(tests, "expected.json"), encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or not isinstance(doc.get("cases"), list):
        raise ValueError("expected.json has no cases list")
    for case in doc["cases"]:
        if case.get("hook", "enforce") != "enforce":
            continue
        if case.get("agents") and agent not in case["agents"]:
            continue
        env = {k: str(v).replace("$SCRIPT_DIR", tests) for k, v in (case.get("env") or {}).items()}
        for tier in RUNNER_TIERS:
            spec = (case.get("tiers") or {}).get(tier)
            if spec is not None:
                yield case, tier, spec, env


def conform(oacb_dir, policy=None):
    """Compare cmdgate with expected.json. Returns a summary with every disagreement listed."""
    policy = policy or Policy.load()
    rows = []
    for case, tier, spec, env in load_cases(oacb_dir):
        code, out, err, audit = run_hook(_compact(case["stdin"]), tier, env, policy, follow_files=False)
        joined = "\n".join(audit)
        row = {"id": case["id"], "tier": tier, "expected_exit": spec.get("exit"), "exit": code,
               "exit_ok": code == spec.get("exit"),
               "rule_ok": spec.get("stderr_contains", "") in err,
               "stdout_ok": spec.get("stdout_contains", "") in out,
               "audit_ok": spec.get("audit_contains", "") in joined,
               "stderr": err[:160], "residual": case["id"].endswith("RESIDUAL"),
               "command": (case["stdin"].get("tool_input") or {}).get("command", "")
               if isinstance(case["stdin"].get("tool_input"), dict) else ""}
        row["ok"] = row["exit_ok"] and row["rule_ok"] and row["stdout_ok"] and row["audit_ok"]
        rows.append(row)
    return {"checks": len(rows), "cases": len({r["id"] for r in rows}),
            "exit_agree": sum(r["exit_ok"] for r in rows), "full_agree": sum(r["ok"] for r in rows),
            "stricter": [r for r in rows if not r["exit_ok"] and r["exit"] == 2],
            "looser": [r for r in rows if not r["exit_ok"] and r["exit"] == 0],
            "other": [r for r in rows if r["exit_ok"] and not r["ok"]]}


def load_legit(oacb_dir):
    """Commands from OACB's false-positive corpus: every line inside a code fence."""
    path = os.path.join(oacb_dir, "false-positive-corpus", "legitimate-commands.md")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    cmds = []
    for block in re.findall(r"```[^\n]*\n(.*?)```", text, re.S):
        cmds += [line for line in block.split("\n") if line.strip()]
    return cmds


def false_positives(oacb_dir, tier="baseline", policy=None):
    policy = policy or Policy.load()
    cmds = load_legit(oacb_dir)
    stopped, warned = [], []
    for c in cmds:
        result = policy.check(c)
        action = decide(result, tier)[0]
        if action in ("block", "ask"):
            stopped.append((c, action, [f["rule"] for f in top_findings(result)]))
        elif action == "warn":
            warned.append((c, action, [f["rule"] for f in top_findings(result)]))
    return {"commands": len(cmds), "tier": tier, "stopped": stopped, "warned": warned}


def _print_conform(s):
    print("OACB enforce-hook cases: %d cases, %d tier checks" % (s["cases"], s["checks"]))
    print("same exit code as expected:          %d / %d" % (s["exit_agree"], s["checks"]))
    print("same exit code, rule id and outputs: %d / %d" % (s["full_agree"], s["checks"]))
    for title, key in (("cmdgate stops, OACB expects allow", "stricter"),
                       ("cmdgate allows, OACB expects block", "looser"),
                       ("same exit, different rule id or output", "other")):
        print("\n%s: %d" % (title, len(s[key])))
        for r in s[key]:
            note = " (documented residual gap in OACB)" if r["residual"] else ""
            print("  [%s] %s%s\n      %s\n      %s" % (r["tier"], r["id"], note, r["command"][:90], r["stderr"]))


def main(argv):
    args = list(argv)
    tier = "baseline"
    if "--tier" in args:
        k = args.index("--tier")
        tier = args[k + 1]
        del args[k:k + 2]
    if args == ["hook"]:
        code, out, err, audit = run_hook(sys.stdin.read(), os.environ.get("OACB_TIER", tier), os.environ)
        log = os.environ.get("OACB_AUDIT_LOG")
        if log and audit:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(log)), exist_ok=True)
                with open(log, "a", encoding="utf-8") as f:
                    f.write("\n".join(audit) + "\n")
            except OSError:
                pass
        if out:
            print(out)
        if err:
            print(err, file=sys.stderr)
        return code
    if len(args) == 2 and args[0] in ("conform", "fp"):
        try:
            if args[0] == "conform":
                _print_conform(conform(args[1]))
            else:
                r = false_positives(args[1], tier)
                print("OACB false-positive corpus at %s tier: %d commands, %d stopped, %d warned"
                      % (tier, r["commands"], len(r["stopped"]), len(r["warned"])))
                for c, a, rules in r["stopped"] + r["warned"]:
                    print("  %-5s %s  <- %s" % (a, c, ", ".join(rules)))
        except (OSError, ValueError) as e:
            print("could not read the OACB checkout at %s: %s" % (args[1], e), file=sys.stderr)
            return 66
        return 0
    print("usage: oacb.py conform <oacb checkout> | fp <oacb checkout> [--tier T] | hook < event.json",
          file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
