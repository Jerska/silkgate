# Contributing

Read this before you change code or documentation in this repository. It covers setup,
tests, commits, and the documentation style that every prose file here follows.
`AGENTS.md` holds the additional instructions for agent contributors.

## Setup

1. Install the three prerequisites: `pip install mitmproxy`, docker, and microsandbox.
2. Run `./cli/silkgate doctor`. It names anything missing and tells you how to install it.

The README's [Layout](README.md#layout) section maps the directories.

## Code

- `cli/` and `mitmaddon/` are dependency-free Python 3 (stdlib only). Keep them that way.
  mitmproxy is the single third-party runtime dependency, and only to run the addon.
- `ui/` is vanilla ES modules: no framework, no build step.
- Minimize state. Prefer clarity over cleverness. Write comments for a reader of the
  file, not for a reviewer of your change.

## Tests

**Run the suite before and after your change.**

```sh
python3 tests.py                        # every suite, sharded, ~11 seconds
python3 -m unittest discover -s test    # python tests only, one process, ~1 minute
python3 mitmaddon/rule_engine.py        # rule-engine self-tests
```

`python3 tests.py` runs every suite, the node ui tests included. It splits the python
tests into shards, one process per shard, and runs the node ui tests (`ui/*.test.js`)
as one more parallel job. `python3 -m unittest discover -s test` runs the python tests
only. If discovery and the shard layout disagree, the runner stops before any test
starts. If you add a python test file, name it in `SHARDS` at the top of `tests.py`.
The runner collects the ui test files with a glob, so a new ui test file needs no
entry.

If mitmproxy is not installed, the addon tests skip and the summary says so. If node is
not on PATH, the ui suite records as one skip. Containment is verified separately with
`./cli/silkgate verify --full`. That command needs docker and msb, and CI runs it on
every push.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org):
`<type>(<scope>): <description>`. The type is one of feat, fix, docs, refactor, test,
chore. The scope is optional (for example `cli`, `mitmaddon`, `image`). Write the
description in the imperative, lowercase. The body explains the why when the title cannot.

Keep history linear: rebase, never merge-commit.

A commit authored inside a silkgate guest carries that session's identity,
`Claude (silkgate/<session>) <claude-<session>@silkgate.invalid>`. That identity marks
the commit as unreviewed guest output and stays through harvest and review. After the
owner reviews the branch, the host agent re-authors the guest commits to the owner's
identity, before the merge to main. The credit moves to the owner, who answers for the
review — never to the agent that operates the host. A host commit carries the owner's
identity from the start.

## Documentation style

**Documentation here is written to be parsed fast — by humans and by agents — so it
follows a controlled style.** The rules derive from ASD-STE100 Simplified Technical
English. They apply to every file in `doc/`, to `README.md`, to `AGENTS.md`, to the
sandboxed-agent skill, and to the sandbox context that `cli/silkgate` generates for
guests. They never apply inside code blocks, identifiers, file paths, or quoted error
messages. Never edit those to fit a prose rule, and count each as one word.

### Structure

- Open every section with its claim, in bold. A reader who stops after that line has the
  rule. The rest of the section is mechanism, example, or proof.
- Bold nothing except that claim.
- Give each document one audience, named in one line under the title: "Read this to …".
- Keep concepts and operations in separate documents: concepts in `doc/ARCHITECTURE.md`,
  proxy operations in `doc/PROXY.md`, threat analysis and the Tier definitions in
  `doc/THREAT-MODEL.md`.
- Collect scattered facts (paths, ports, hosts) into a table. Draw a flow of more than
  three steps as a diagram.
- Tie every guarantee to its proof: name the test file or verify check that pins it.
- Define each term once — guest, session, profile, Tier 1, Tier 2 live in the
  ARCHITECTURE glossary — and never introduce a synonym for a defined term.

### Sentences

- Classify before you write. Procedural text instructs: imperative mood, one instruction
  per sentence, at most 20 words. Descriptive text explains: simple tenses, at most 25
  words, one topic per paragraph. Never mix the two in one passage.
- Write complete sentences: no fragments, no arrow chains, no `=` or `→` in place of a
  verb.
- No contractions. No semicolons.
- Use simple verb forms only: no present perfect, no "-ing" verb forms. Prefer active
  voice.
- Use only these modals: can, will, must. Never write should, would, may, might, or
  could.
- Put the condition before the command: "If the test fails, read the log."
- In a warning, put the command first and the risk second: "Do not run this against
  production. The command deletes rows."

### Words

- One word, one meaning across a document. Pick one of check, verify, confirm — and keep
  it.
- Keep noun chains to three words. Break longer ones with prepositions.
- Delete words that carry no fact: simply, robust, comprehensive, "in order to".
- Write "for example", never "e.g.". Use American spelling.

### Self-check and doc-testing

Before you commit prose: scan for contractions, semicolons, "should", "has been", and
"-ing" verbs. Count the words in your three longest sentences and split any over the
limit.

Test a document the way it will be used: hand it to a fresh agent that has read nothing
else, ask it to perform the task, and fix what it had to guess. Repeat until a review
pass reports nothing it believes in.
