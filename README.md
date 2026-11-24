# cmdgate

A pre-execution check for shell commands that AI coding agents want to run. It parses the command into the commands that would really execute, scores each one against structured rules, and returns allow, warn, ask or block with the evidence for the decision.

This is an independent prototype that I built on my own. It is not affiliated with, endorsed by, or reviewed by Unbound. The benchmark corpora are synthetic and written by me. The only non-synthetic inputs are the public conformance cases and false-positive corpus in Unbound's open source OACB repository, which I read from a local clone and do not redistribute here.

## The problem

Coding agents run shell commands through a tool call, and the guardrail in front of that call usually matches patterns against the command string. The string is not the command. `rm -rf ~`, `X=rm; $X -rf ~`, `echo 'rm -rf ~' | sh` and `bash cleanup.sh` (where the script contains the `rm`) all do the same thing and share almost no text. In the other direction, `git commit -m "revert: rm -rf ~"` contains the text and does nothing. A string matcher has to choose between missing the first group and flagging the second.

## Why this matters to Unbound specifically

What I verified from public sources:

- Unbound's site describes a policy engine that intercepts agent actions before they run through the hooks and managed settings agents already expose, and shows an agent being paused on `rm -rf ./migrations && npm run db:reset` (https://getunbound.ai/).
- The intern posting says the product spans agent discovery, an LLM gateway and a runtime policy engine, and that past intern projects included policy engine rules (https://www.ycombinator.com/companies/unbound/jobs/hn66xKN-software-engineering-intern).
- Unbound maintains OACB, an open baseline of Claude Code and Codex hooks (https://github.com/websentry-ai/oacb). Its Bash enforcement hook, `baseline/shared/oacb-enforce-core.sh`, normalises whitespace, replaces quoted spans with a placeholder, and then runs `grep -E` rules over the string. It classifies each rule as low, medium, high or critical and maps tier and risk to allow, warn, ask or block.
- OACB is open about the limit of that approach. Its README says pattern-match rules can be defeated by obfuscation the agent controls, `non-claims.md` lists "write a shell script to /tmp and invoke it" and Python one-liners as things a denylist does not catch, and three conformance cases are marked `RESIDUAL`, including `echo 'rm -rf ~' | sh`, which is expected to be allowed at baseline.
- OACB's conformance suite is a public JSON format (`conformance-tests/expected.json`): a hook name, the stdin event, and for each tier the expected exit code and a rule id that must appear on stderr.

So the question I tried to answer is narrow: if the Bash hook parsed the command instead of grepping it, using the same risk levels, tiers, exit codes and audit log keys, how many of OACB's own cases would it agree on, how many of its documented residual gaps would it close, and what would it cost in false positives on OACB's own list of legitimate commands?

I do not know how Unbound's commercial policy engine works internally, and nothing here claims to describe it.

## What it does

- Lexes the command with a shell-aware lexer (quotes, escapes, `$'..'`, operators, redirects, heredocs, `$( )`, backticks, `<( )`).
- Resolves what would run: strips wrappers (`sudo`, `env`, `timeout`, `xargs`, `npx` and others) and follows `sh -c`, `eval`, `trap`, substitutions, `find -exec`, `ssh host '...'`, `docker exec` and `kubectl exec --`.
- Expands what can be known statically inside the one command string: variables and aliases assigned earlier, `${VAR:-default}`, `${IFS}`, brace expansion, and `$(echo ..)` or `$(printf ..)` of literals. Anything it cannot resolve stays unresolved and is flagged as such; it never guesses.
- Tracks literal text through a pipe, so `echo .. | sh`, `echo .. | base64 -d | bash`, heredocs and here-strings fed to a shell are analysed as scripts. A heredoc fed to `cat > file` is data and is not.
- Tracks files written by `echo`, `printf`, `cat <<EOF` or `tee` earlier in the same command, so `printf '..' > x.sh && sh x.sh` is analysed.
- When the hook event carries a `cwd`, reads (never runs) small shell scripts and `package.json` scripts that the command would execute. `npm run db:reset` is judged by what the script does.
- For `python -c`, `node -e`, `perl -e`, `ruby -e` and `php -r`, applies a heuristic: if the code calls a shell-out API, its string literals are analysed as shell commands, and recursive delete APIs become an equivalent `rm -rf` on the literal paths.
- Matches 49 rules in `policy.json` against the resolved commands. Each rule has a risk level, and 25 carry the id of the OACB rule they correspond to.
- Turns the highest risk into an action using the same tier matrix as OACB (shadow, receipts, baseline, strict, paranoid).
- Reports the rule, the exact command that matched, the chain of wrappers it was found through, and what was resolved to get there.

## Architecture

```
shparse.py   lexer, heredocs, word segments, static expansion, echo/printf/base64 output   (470 lines)
resolve.py   Analyzer: walks pipelines in order and returns the commands that would run    (426 lines)
cmdgate.py   Policy (rule matching), risk and tier decision, check and hook CLI           (271 lines)
policy.json  49 rules: structure to match, risk, optional OACB rule id
oacb.py      OACB hook contract, audit line, conformance and false-positive runners       (260 lines)
corpus.py    synthetic development and held-out corpora
bench.py     measurements; writes bench_results.json
demo.py      one minute tour
```

Data flow: command string, then tokens, then pipelines of words, then expansion with the state known so far, then a flat list of "leaves" (one per simple command, with name, flags, positionals, redirects, pipeline neighbours and the wrapper chain), then rule matches, then one risk, then one action per tier.

## Key decisions and tradeoffs

- **Over-approximate, and say when I am doing it.** `${CMD:-rm}` is treated as `rm` even though `CMD` might be set. An alias defined on the same line is expanded even though bash would not expand it in a non-interactive shell. A function body is analysed where it is defined. For a gate, a false "this would run" is cheaper than a false "this would not".
- **Unresolved is a finding, not a pass.** A command name that is still `$X` after expansion is `dynamic-command` (medium). `eval` of run-time text is critical, the same as OACB's eval rule. A command that does not parse is high.
- **Risk on the rule, action from the tier.** The first version had warn and block baked into each rule. Moving to risk plus OACB's tier matrix made the output comparable with OACB case by case, and let `rm -rf node_modules` be medium (allowed at baseline, warned at strict) instead of a warning everywhere.
- **Report the resolved rule, not the obfuscation.** For `\rm -rf /` OACB expects its backslash rule (OBF-001). cmdgate removes the backslash and reports the delete rule (RM-001). That is 6 of the 8 conformance differences below. I think naming what the command does is more useful in an audit log, but it means rule ids do not always line up.
- **Fail closed.** The first version's hook crashed on malformed JSON, and a crashing hook exits 1, which is not a block (OACB's hook comments give the contract as exit 2 to block). Now empty, oversized or malformed input, a policy that will not load, and an internal exception all produce a deny.
- **Ask is a block in the OACB contract.** OACB prompts on `/dev/tty` and blocks after 30 seconds. My hook never prompts, so ask exits 2. In the Claude Code JSON contract (`cmdgate.py hook`) ask is returned as `permissionDecision: "ask"` instead.
- **Reading files is bounded and optional.** Only regular files up to 256 KB, no binaries, only when a `cwd` is supplied, and `--no-follow` turns it off. The files read are listed in the audit line. A file can change between the check and the run; that race is not closed.
- **Work is bounded.** Nesting depth 8 and 2000 commands per check, after which the result is "unparseable". A 692 KB nested command returns in under two seconds in the test suite.

## Install and usage

Standard library only, nothing to install. Written for Python 3.9 or newer and tested on 3.13.

```
python demo.py
python cmdgate.py check 'cd app && rm -rf ./migrations && npm run db:reset'
python cmdgate.py --tier strict --cwd . check 'bash scripts/cleanup.sh'
echo '{"tool_name":"Bash","tool_input":{"command":"git push -f origin main"}}' | python cmdgate.py hook
echo '{"tool_name":"Bash","tool_input":{"command":"git push -f origin main"}}' | OACB_TIER=strict python oacb.py hook
python -m unittest
python bench.py
```

`check` exits 0, 1 or 2 for allow, warn or block. `cmdgate.py hook` speaks Claude Code's JSON contract and always exits 0. `oacb.py hook` speaks OACB's contract: exit 2 to block, rule on stderr, and an audit line appended to `$OACB_AUDIT_LOG` if that is set.

To compare against OACB you need your own clone:

```
git clone https://github.com/websentry-ai/oacb /tmp/oacb
python oacb.py conform /tmp/oacb
python oacb.py fp /tmp/oacb --tier baseline
python bench.py --oacb /tmp/oacb
```

## A real example

Output of `python cmdgate.py --tier strict check "sudo sh -c 'X=rm; \$X -rf \"\$HOME\"'"`, first finding only:

```
{
  "action": "block",
  "risk": "critical",
  "commands": 3,
  "findings": [
    {
      "rule": "rm-protected-path",
      "risk": "critical",
      "action": "block",
      "why": "recursive delete of a root, home, system, parent or .git path",
      "command": "rm -rf $HOME",
      "via": ["sudo", "sh -c"],
      "oacb": "OACB-RM-001",
      "resolved": ["$X -> 'rm'"]
    },
    ...
  ],
  "tier": "strict",
  "decision": "block"
}
```

From `python demo.py`, a command whose effect is in a file, run through the OACB-style hook at baseline tier:

```
$ npm run db:reset
  risk=critical  baseline=block  strict=block
  rule: prisma-migrate-reset  (OACB equivalent: OACB-DB-002)
  ran:  prisma migrate reset --force
  via:  npm run db:reset

[baseline tier] exit=2
  stderr: cmdgate baseline [prisma-migrate-reset / OACB-DB-002]: prisma migrate reset drops every table [prisma migrate reset --force]
  audit:  {"ts":"2026-11-24T00:28:26Z","decision":"deny","tier":"baseline","rule":"prisma-migrate-reset","risk":"critical","risk_taxonomy_version":"1.0","reason":"prisma migrate reset drops every table [prisma migrate reset --force]","cmd":"cd app && rm -rf ./migrations && npm run db:reset","oacb_version":"0.2.1","engine":"cmdgate","evidence":{"command":"prisma migrate reset --force","via":["npm run db:reset"],"files_read":["<cwd>/package.json"]},"oacb_rule":"OACB-DB-002"}
```

## Tests and verified results

`python -m unittest` runs 89 tests: the 28 from the first version, unchanged, and 61 new ones covering expansion, heredocs, pipes, file following, inline code, policy validation, tiers, the hook contracts and failure cases. All pass, also under `python -W error`.

All numbers below are from runs on my machine. They are in `bench_results.json`.

### OACB's own cases (not written by me)

Run against OACB at commit `8ed8d1d`. There are 71 cases for the enforce hook, which the OACB runner expands to 93 tier checks.

| | result |
|---|---|
| same exit code as `expected.json` | 91 / 93 |
| same exit code, rule id on stderr, stdout and audit substrings | 85 / 93 |
| cmdgate allows where OACB expects a block | 0 |
| cmdgate stops where OACB expects allow | 2 |
| OACB false-positive corpus (255 legitimate commands), baseline tier | 0 stopped, 0 warned |
| same corpus, strict tier | 0 stopped, 2 warned (`git branch -D old-branch`, `find . -name "*.pyc" -delete`) |

The 2 stricter cases are both ones OACB marks `RESIDUAL`: `echo 'rm -rf ~' | sh`, which cmdgate resolves to the `rm`, and `cat ~/.aws/credentials`, which OACB leaves to its Read deny rules. The third residual, `nslookup` exfiltration, cmdgate also allows. The 6 rule id differences are cases where OACB expects an obfuscation rule and cmdgate reports the underlying rule, as described above.

Context for these numbers: I read OACB's rules and cases before writing this version and wrote rules to cover the same families, so this is a conformance target, not a blind test. The numbers above are from the first time I ran the suite and I did not change anything in response. For comparison, the first version of cmdgate agreed with 39 of the 65 baseline-tier Bash checks; this version agrees with 63 of the same 65.

### Synthetic corpora (written by me)

Development corpus, which the parser was built against: 71 risky forms through 16 single rewrites, 35 benign commands through the same rewrites, and every risky form as inert text in 5 lookalike positions.

| detector | risky flagged | benign flagged |
|---|---|---|
| prefix globs | 147 / 1136 (12.9%) | 20 / 915 (2.2%) |
| substring globs | 587 / 1136 (51.7%) | 229 / 915 (25.0%) |
| cmdgate | 1136 / 1136 (100.0%) | 0 / 915 (0.0%) |

The first version caught 1 of 10 commands in a "known hard" set. This version was developed against that set and catches 9; `make nuke` is still allowed because Makefiles are not read.

Held-out corpus: 34 different base commands, 26 different rewrites (none identical to a development rewrite), one or two composed at random with seed 20261123, plus 10 new lookalike positions. I wrote the generator, checked every command with `bash -n`, froze the parser and rules, and ran it once. This is that first run:

| detector | risky flagged | benign flagged |
|---|---|---|
| substring globs | 263 / 800 (32.9%) | 136 / 800 (17.0%) |
| first version of cmdgate | 379 / 800 (47.4%) | 30 / 800 (3.8%) |
| cmdgate, frozen | 764 / 800 (95.5%) | 5 / 800 (0.6%) |

None of the 5 benign flags was a stop at baseline tier. The 36 misses and 5 false positives came from three bugs: `trap '<command>' EXIT` was not followed (35 of the misses), an assignment directly after `{` or `then` was not recognised as an assignment, and `\n` inside a string literal in inline Python was not unescaped. I fixed those three and added tests. After the fixes the same 800 + 800 commands score 800 / 800 and 0 / 800, which is no longer a held-out result. A second sample from the same generator with seed 7, run once after the fixes, scores 799 / 800 and 0 / 800; the miss is `python3 -c 'import os; os.system("git${IFS}reset${IFS}--hard${IFS}origin/main")'`, because the inline code heuristic skips string literals without a space.

What this does and does not show. It shows that resolving the command handles the rewrite families I thought of, with few false positives on text that only looks risky, and that the first held-out run found real bugs. It does not show resistance to an adversary: I wrote both corpora, the second sample shares its generator with the first, and none of this is real agent traffic.

Timing over two runs of `bench.py`: a check takes a median of 84 to 96 microseconds in process (p99 8 to 12 ms) over 5251 commands. As a subprocess per tool call the hook took a median of 157 to 193 ms, which is almost all Python startup.

## Limitations and next steps

- Static analysis has a ceiling. Values that only exist at run time (`$1`, command output, files fetched earlier in the session, environment variables) are not resolved. They are flagged where they decide the command name, and ignored elsewhere.
- Makefiles, `just`, task runners other than `package.json` scripts, and scripts in languages other than shell are not read.
- The inline code handling is a regex heuristic over string literals, not a parser for Python or JavaScript. String concatenation, f-strings or `getattr` tricks defeat it.
- Operations split across several tool calls are only caught when the later call runs a file that is on disk at check time. There is no session state.
- File following has a check-then-run race and trusts the `cwd` in the hook event.
- Shell coverage is partial: no arithmetic evaluation, no arrays, no `case` patterns, no glob resolution, and `for` loop variables are treated as unknown.
- The rules and risk levels are my reading of OACB's public rules plus my own judgment. The trusted installer host list is the one in OACB's hook.
- It only covers the Bash tool. File edits, MCP tool calls, prompts and network egress are out of scope.
- I did not publish a comparison of OACB's own hook on my corpora. OACB's `SECURITY.md` asks that rule bypasses be reported privately, so this repo only reports results on cases OACB itself has published.
- `cmdgate.py hook` follows the Claude Code PreToolUse JSON format as I understand it and is tested with constructed events. I have not run either hook inside a live agent session.

Next steps I would take: run it in shadow mode on real agent command logs to measure false positives that matter, add session state so a file written by an earlier Write or Bash call is tracked without touching disk, replace the inline code heuristic with Python's `ast` module for the Python case, and port the hook to a compiled language or a long-lived process to remove the startup cost.
