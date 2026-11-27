# Contributing

Read this before you change code or docs here. `AGENTS.md` adds the rules for agent
contributors.

## Setup

```sh
pip install mitmproxy          # plus docker and microsandbox
./cli/silkgate doctor          # names anything missing, with its install command
```

The README's [Layout](README.md#layout) maps the directories.

## Code

- `cli/` and `mitmaddon/` are stdlib-only Python 3. Keep them that way. mitmproxy is the one
  third-party dependency, and only the addon needs it.
- `ui/` is vanilla ES modules: no framework, no build step.
- Minimize state. Prefer clarity over cleverness. Write comments for a reader of the file,
  not for a reviewer of your change.

## Tests

**Run the suite before and after your change. A change to comments alone needs only a
syntax check.**

```sh
python3 tests.py                        # everything, sharded, ~15 s
python3 -m unittest discover -s test    # python only, one process, ~1 min
python3 mitmaddon/rule_engine.py        # rule-engine self-tests
./cli/silkgate verify --full            # containment; needs docker and msb (CI runs it)
python3 test/smoke_claude.py            # the claude profile in a real guest (CI runs it)
```

- Comments alone: `python3 -m py_compile <file>`, `node --check <file>`, or `sh -n <file>`.
  A docstring a program reads counts as code: `cli/silkgate_cli/core.py`'s module
  docstring is `silkgate --help`.
- A new python test file goes in `SHARDS` at the top of `tests.py`. The runner refuses to
  start if discovery and `SHARDS` disagree.
- A new ui test file (`ui/*.test.js`) needs no entry: the runner globs for them.
- Without mitmproxy, the addon tests skip. Without node, the ui suite counts as one skip.
  The summary says so either way.

## Commits

[Conventional Commits](https://www.conventionalcommits.org), imperative and lowercase:

```text
fix(cli): refuse a mount that hides the workspace
docs: split the proxy reference out of the README
```

- Types: feat, fix, docs, refactor, test, chore. The scope is optional (`cli`, `mitmaddon`,
  `ui`, `profiles`, …).
- Use the body for the why, when the title can't carry it.
- Keep history linear: rebase, never merge.

**Guest commits stay marked as unreviewed until the owner reviews them.** A commit made
inside a guest carries the session's identity:

```text
Claude (silkgate/<session>) <claude-<session>@silkgate.invalid>
```

After review, the host agent re-authors those commits to the owner before the merge to
main. The owner answers for the review, so the credit goes to them, never to the host agent.
Host commits carry the owner's identity from the start.

## Documentation style

**Write for a reader who skims: short sentences, examples first, nothing they don't need.**

This applies to the README, `doc/`, `AGENTS.md`, the sandboxed-agent skill, each profile's
`context.md`, and the guest context that `cli/silkgate` generates. It never applies inside
code blocks, identifiers, paths, or quoted messages.

- Open each section with its claim, in bold. Bold nothing else.
- Show, then explain. A command, a table, or an example beats a paragraph.
- Keep sentences short. Split one that needs both a dash and an "and".
- Prefer clarity over completeness. Keep only what the reader needs to act, and link to
  the rest.
- Give each document one audience, in one line under the title: "Read this to …".
- Give each section one topic. Split a section that does two things. Move reference detail
  into its own file and link to it.
- State each fact once. Elsewhere, link to it. A doc table that copies code gets a
  `<!-- Mirrors X in file. Update both. -->` comment, and the code a matching
  `Mirrored in doc.md` comment.
- Use the glossary terms from [ARCHITECTURE](doc/ARCHITECTURE.md#glossary) as defined:
  guest, session, profile, Tier 1, Tier 2.
- Lists and tables may use fragments. Paragraphs use full sentences.
- End a section that makes a guarantee with a `Pinned by:` line that names its test or
  verify check.
- Write "for example", not "e.g.". Use American spelling.

Before you commit prose, read it as a new user. If they can't do the task without opening
the code, add the missing example.
