# cmdgate

Decide whether a shell command from an AI coding agent should be allowed, warned on, or blocked, by parsing the command instead of pattern matching the string.

Coding agents run shell commands through a tool call, and the usual guardrail is a deny list of globs such as `rm -rf *` or `git push --force*`. Those rules match the text of the command, not what it does. `sudo rm -fr /` and `bash -c 'cd app && rm -r -f /'` get past them, and `git commit -m "revert: rm -rf /"` gets flagged by the looser ones. I built `cmdgate` to see how far a small parser gets on that problem. The idea came from reading about runtime policy enforcement for agent tool calls, where a decision has to be made before the command executes and has to say why.

It is one Python file (about 400 lines) plus a JSON policy, with no dependencies.

## Results

`python bench.py` generates a labelled corpus. Each of 26 destructive commands and their flag variants (71 forms) goes through 16 rewrites that keep its effect, such as a `sudo` prefix, an absolute path, `bash -c`, `eval`, a `$( )` substitution, or a quoted command name. Benign commands are 35 ordinary commands through the same rewrites, plus every risky form in a place where it is not executed (an `echo`, a commit message, a `grep` pattern, a comment, a `printf` into a file).

| detector | risky caught | benign flagged |
|---|---|---|
| prefix globs | 147 / 1136 (12.9%) | 20 / 915 (2.2%) |
| substring globs | 587 / 1136 (51.7%) | 229 / 915 (25.0%) |
| cmdgate | 1136 / 1136 (100.0%) | 4 / 915 (0.4%) |

The 100% needs context. I wrote the corpus and the parser, so the rewrites are the ones I thought of, and the glob list is 29 patterns I wrote by hand for the canonical commands. The table shows that parsing handles the rewrites I know about. It does not show that the tool is hard to evade.

To keep that honest, the benchmark also runs a second set of 10 commands that I wrote to break it. cmdgate catches 1 of the 10. The substring globs catch 3 of them, because the text `rm -rf` is still visible in some.

```
allow X=rm; $X -rf /
allow $(echo rm) -rf /
allow alias r=rm; r -rf /
allow python3 -c "import shutil; shutil.rmtree('/')"
allow perl -e 'system("rm -rf /")'
allow node -e "require('fs').rmSync('/', {recursive: true})"
allow printf 'rm -rf /' > x.sh && sh x.sh
allow ssh prod 'rm -rf /srv/app'
allow make nuke
block echo cm0gLXJmIC8K | base64 -d | sh
```

The 4 false positives are all the same case: `grep -rn 'cat ~/.ssh/id_rsa' docs/`. The credential rule looks at positional arguments of `grep`, and it cannot tell that the first one is a search pattern and not a file. I left it in the results instead of special-casing it.

A check takes a median of 30 to 35 microseconds in process over three runs. Run as a separate process per tool call, the hook took a median of 134 to 172 ms on this machine, which is almost all Python startup.

## How it works

1. A lexer written for this removes quotes and escapes and splits on `&&`, `||`, `;`, `|`, `&`, newlines and parentheses. Redirect targets are kept separately from arguments. `$( )` and backtick bodies are collected for later.
2. Each simple command is resolved to what actually runs. Leading `VAR=value` assignments and wrappers (`sudo`, `env`, `timeout`, `nohup`, `xargs`, `nice` and others) are stripped and recorded. `bash -c`, `sh -lc`, `eval`, `find -exec` and command substitutions are parsed recursively, up to 8 levels.
3. Each resulting command is normalised: basename of the program, a set of flags with combined short flags expanded (`-fr` becomes `-f` and `-r`), and positionals with option values removed (`git -C repo push` has `push` as its first positional).
4. Rules in `policy.json` match on that structure: command name, subcommand, required flags, excluded flags, a regex over positionals or arguments, the commands later in the same pipeline, and redirect targets. There are 26 rules. The decision is the highest action of any match.

Every finding names the rule, the exact command that matched, and the wrappers it was found inside:

```
$ python cmdgate.py check "sudo sh -c 'terraform destroy -auto-approve'"
{
  "action": "block",
  "commands": 2,
  "findings": [
    {"rule": "iac-destroy", "action": "block", "why": "destroys managed infrastructure",
     "command": "terraform destroy -auto-approve", "via": ["sudo", "sh -c"]}
  ]
}
```

(Output reflowed here to save space.) The exit code is 0 for allow, 1 for warn and 2 for block.

Two decisions I would defend. A command that fails to parse (an unterminated quote, nesting past the limit) is a warning, not an allow. And the hook mode only ever tightens: it prints `deny` for a block and `ask` for a warning, and prints nothing for an allow, so it never approves a command on the agent's behalf.

## Hook mode

`python cmdgate.py hook` reads a PreToolUse style JSON event on stdin (`{"tool_name": "Bash", "tool_input": {"command": "..."}}`) and prints a `hookSpecificOutput` object with `permissionDecision` and a reason. I wrote this from the hook format as I understand it and tested it with hand-written events only. I have not run it inside a live agent session.

## Limits

- The corpus is synthetic and I wrote both sides of the comparison. It has not been run on real agent command logs.
- It is not integrated with any product or gateway, and the rules are my own guesses at a reasonable policy.
- It does not track variables, aliases or functions, and it does not look inside scripts, Makefiles, or code passed to `python -c`, `node -e` or `perl -e`. The known-hard set above shows this.
- Heredoc bodies are parsed as if they were commands, which can over-flag.
- `ssh host 'command'` and `docker exec` are not unwrapped.
- It only covers shell commands. File edits, MCP tool calls and network requests are out of scope.
- Static parsing has a ceiling here. A command that builds another command at run time needs either a sandbox or a model to judge it. I think the useful role for a parser is the fast first pass that produces evidence, not the whole answer.

## Run it

```
python test_cmdgate.py
python bench.py
python cmdgate.py check 'cd app && rm -rf ./migrations && npm run db:reset'
```

Python 3.9 or newer. Nothing to install.
