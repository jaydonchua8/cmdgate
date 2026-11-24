"""Measure cmdgate on the synthetic corpora in corpus.py, and optionally on an OACB checkout.

    python bench.py                 development corpus, held-out corpus, timing
    python bench.py --oacb DIR      also run OACB's conformance cases and false-positive corpus

The corpora are synthetic and written by me. See README.md for what the numbers
do and do not show.
"""
import fnmatch
import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import corpus
from cmdgate import Policy, decide

ANYWHERE = ["*" + g.strip("*") + "*" for g in corpus.GLOBS]

# Recorded, not recomputed: the one run of the held-out corpus (seed 20261123) made
# with the parser frozen, before I looked at any of its failures. "first version" is
# the single-file cmdgate this repo started from. The current code has since been
# fixed against those failures, so rerunning cannot reproduce this row.
FIRST_RUN = {
    "substring globs": {"caught": 263, "risky": 800, "false_positives": 136, "benign": 800},
    "first version": {"caught": 379, "risky": 800, "false_positives": 30, "benign": 800},
    "cmdgate, frozen": {"caught": 764, "risky": 800, "false_positives": 5, "benign": 800},
}


def glob_flag(patterns, cmd):
    return any(fnmatch.fnmatchcase(cmd, p) for p in patterns)


def pct(a, b):
    return "%.1f%%" % (100.0 * a / b)


def score(policy, risky, benign):
    times = []
    for row in risky + benign:
        t = time.perf_counter()
        d = policy.check(row["cmd"])
        times.append((time.perf_counter() - t) * 1e6)
        row["got"] = d["action"]
        row["tier"] = decide(d, "baseline")[0]
        row["prefix"] = glob_flag(corpus.GLOBS, row["cmd"])
        row["anywhere"] = glob_flag(ANYWHERE, row["cmd"])
    return times


def table(risky, benign):
    out = {}
    print("\n| detector | risky flagged | benign flagged |")
    print("|---|---|---|")
    for label, key in (("prefix globs", "prefix"), ("substring globs", "anywhere"), ("cmdgate", "got")):
        hit = (lambda r: r[key] != "allow") if key == "got" else (lambda r: r[key])
        c, f = sum(map(hit, risky)), sum(map(hit, benign))
        out[label] = {"caught": c, "risky": len(risky), "false_positives": f, "benign": len(benign)}
        print("| %s | %d / %d (%s) | %d / %d (%s) |" % (label, c, len(risky), pct(c, len(risky)),
                                                      f, len(benign), pct(f, len(benign))))
    out["exact_level"] = sum(r["got"] == r["expected"] for r in risky)
    out["benign_stopped_at_baseline"] = sum(r["tier"] in ("ask", "block") for r in benign)
    print("cmdgate same level as the label (warn vs block): %d / %d" % (out["exact_level"], len(risky)))
    print("benign commands stopped at baseline tier (ask or block): %d / %d"
          % (out["benign_stopped_at_baseline"], len(benign)))
    return out


def by_rewrite(risky, key="rewrite"):
    groups = {}
    for r in risky:
        for name in (r.get("rewrites") or [r[key]]):
            g = groups.setdefault(name, [0, 0, 0])
            g[0] += 1
            g[1] += r["anywhere"]
            g[2] += r["got"] != "allow"
    print("\n| rewrite | samples | substring globs | cmdgate |")
    print("|---|---|---|---|")
    for name, (n, a, c) in sorted(groups.items(), key=lambda kv: (kv[1][2] / kv[1][0], kv[0])):
        print("| %s | %d | %s | %s |" % (name, n, pct(a, n), pct(c, n)))


def show(title, rows, limit=10):
    print("\n%s: %d" % (title, len(rows)))
    for r in rows[:limit]:
        print("  " + r["cmd"].replace("\n", "\\n")[:150])


def main(argv):
    policy = Policy.load()
    summary = {}

    risky, benign = corpus.dev()
    print("== development corpus: %d risky, %d benign (the parser was built against this) ==" % (len(risky), len(benign)))
    times = score(policy, risky, benign)
    summary["dev"] = table(risky, benign)
    show("misses", [r for r in risky if r["got"] == "allow"])
    show("false positives", [r for r in benign if r["got"] != "allow"])
    hard = [(c, policy.check(c)["action"]) for c in corpus.KNOWN_HARD]
    summary["dev"]["known_hard_caught"] = sum(a != "allow" for _, a in hard)
    summary["dev"]["known_hard_total"] = len(hard)
    print("\nknown-hard set (the first version caught 1 / 10; now development data): %d / %d"
          % (summary["dev"]["known_hard_caught"], len(hard)))
    for c, a in hard:
        print("  %-5s %s" % (a, c))

    print("\n== held-out corpus, as recorded on its first run with the parser frozen ==")
    print("| detector | risky flagged | benign flagged |")
    print("|---|---|---|")
    for label, v in FIRST_RUN.items():
        print("| %s | %d / %d (%s) | %d / %d (%s) |" % (label, v["caught"], v["risky"], pct(v["caught"], v["risky"]),
                                                      v["false_positives"], v["benign"], pct(v["false_positives"], v["benign"])))
    summary["heldout_first_run_recorded"] = FIRST_RUN

    for label, seed in (("heldout_after_fixes", 20261123), ("second_sample", 7)):
        risky, benign = corpus.heldout(seed=seed)
        note = "same commands as the first run, after fixing its failures (no longer held out)" if seed != 7 \
            else "a second sample from the same generator, different seed"
        print("\n== held-out generator, seed %d: %s ==" % (seed, note))
        times += score(policy, risky, benign)
        summary[label] = table(risky, benign)
        if seed != 7:
            by_rewrite(risky)
        show("misses", [r for r in risky if r["got"] == "allow"])
        show("false positives", [r for r in benign if r["got"] != "allow"])

    times.sort()
    med, p99 = statistics.median(times), times[int(len(times) * 0.99)]
    print("\nin-process check: median %.0f us, p99 %.0f us over %d commands" % (med, p99, len(times)))
    event = json.dumps({"tool_name": "Bash", "tool_input": {"command": "cd app && rm -rf ./migrations && npm run db:reset"}})
    spawn = []
    for _ in range(20):
        t = time.perf_counter()
        subprocess.run([sys.executable, os.path.join(HERE, "cmdgate.py"), "hook"], input=event, text=True,
                       capture_output=True, check=True)
        spawn.append((time.perf_counter() - t) * 1e3)
    print("hook as a subprocess (python startup included): median %.0f ms over 20 runs" % statistics.median(spawn))
    summary["timing"] = {"median_us": round(med), "p99_us": round(p99), "hook_median_ms": round(statistics.median(spawn))}

    if "--oacb" in argv:
        import oacb
        path = argv[argv.index("--oacb") + 1]
        print("\n== OACB checkout at %s ==" % path)
        s = oacb.conform(path, policy)
        oacb._print_conform(s)
        summary["oacb_conformance"] = {
            "cases": s["cases"], "checks": s["checks"], "exit_agree": s["exit_agree"], "full_agree": s["full_agree"],
            "stricter": [r["id"] for r in s["stricter"]], "looser": [r["id"] for r in s["looser"]]}
        for tier in ("baseline", "strict"):
            fp = oacb.false_positives(path, tier, policy)
            print("\nOACB false-positive corpus at %s tier: %d commands, %d stopped, %d warned"
                  % (tier, fp["commands"], len(fp["stopped"]), len(fp["warned"])))
            for c, a, rules in fp["stopped"] + fp["warned"]:
                print("  %-5s %s  <- %s" % (a, c, ", ".join(rules)))
            summary["oacb_false_positive_corpus_" + tier] = {
                "commands": fp["commands"], "stopped": len(fp["stopped"]), "warned": len(fp["warned"])}

    with open(os.path.join(HERE, "bench_results.json"), "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1:])
