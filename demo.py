"""A one minute tour: python demo.py

Runs offline. It builds a throwaway project directory so the file-following part
has something real to read, and deletes it at the end.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oacb
from cmdgate import Policy, decide, top_findings, TIERS

P = Policy.load()


def show(cmd, **kw):
    d = P.check(cmd, **kw)
    tiers = "  ".join("%s=%s" % (t, decide(d, t)[0]) for t in ("baseline", "strict"))
    print("\n$ " + cmd.replace("\n", "\n  "))
    print("  risk=%s  %s" % (d["risk"], tiers))
    for f in top_findings(d)[:1]:
        print("  rule: %s%s" % (f["rule"], "  (OACB equivalent: %s)" % f["oacb"] if f.get("oacb") else ""))
        print("  ran:  %s" % f["command"])
        if f["via"]:
            print("  via:  %s" % " -> ".join(f["via"]))
        if f.get("resolved"):
            print("  resolved: %s" % "; ".join(f["resolved"]))


print("1. The same destructive command, written eight ways. A regex on the string sees eight different strings.")
for c in ("rm -rf ~", "sudo \\rm -fr ~", "X=rm; $X -rf ~", "$(echo rm) -rf ~", "rm${IFS}-rf${IFS}$HOME",
          "echo 'rm -rf ~' | sh", "echo cm0gLXJmIH4K | base64 -d | bash",
          "python3 -c \"import os; os.system('rm -rf ~')\""):
    show(c)

print("\n\n2. The same text where it is only data. These must not be stopped.")
for c in ("git commit -m 'revert: rm -rf ~'", "cat <<'EOF' > RUNBOOK.md\nnever run rm -rf ~\nEOF",
          "grep -rn 'terraform destroy' docs/", "rm -rf node_modules"):
    show(c)

print("\n\n3. Commands that hide the action in a file. With the hook's cwd, the file is read (never run).")
with tempfile.TemporaryDirectory() as cwd:
    with open(os.path.join(cwd, "package.json"), "w") as f:
        json.dump({"scripts": {"db:reset": "prisma migrate reset --force", "build": "tsc -p ."}}, f)
    with open(os.path.join(cwd, "cleanup.sh"), "w") as f:
        f.write("#!/bin/bash\nset -e\ngit clean -fdx\ngit push --force origin main\n")
    for c in ("npm run build", "npm run db:reset", "bash cleanup.sh"):
        show(c, cwd=cwd, follow_files=True)

    print("\n\n4. As a PreToolUse hook with OACB's contract: exit 2 blocks, the rule goes to stderr,")
    print("   and one audit line is written per decision.")
    event = json.dumps({"tool_name": "Bash", "cwd": cwd, "session_id": "demo",
                        "tool_input": {"command": "cd app && rm -rf ./migrations && npm run db:reset"}})
    for tier in ("baseline", "strict"):
        code, out, err, audit = oacb.run_hook(event, tier, policy=P)
        print("\n[%s tier] exit=%d" % (tier, code))
        print("  stderr: " + (err or "(empty)"))
        print("  audit:  " + audit[0].replace(cwd, "<cwd>"))

print("\n\n5. Failure cases fail closed.")
for label, raw in (("empty stdin", ""), ("not JSON", "{oops"), ("no command", '{"tool_name": "Bash"}'),
                   ("unterminated quote", json.dumps({"tool_name": "Bash", "tool_input": {"command": 'rm -rf "/'}}))):
    code, _, err, _ = oacb.run_hook(raw, "strict", policy=P)
    print("  %-20s exit=%d  %s" % (label, code, err))
