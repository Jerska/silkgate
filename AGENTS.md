# Agent instructions

Read this to contribute to silkgate as a coding agent.

- The rules of @CONTRIBUTING.md apply to agents in full: setup, code constraints,
  tests, and commit conventions.
- Documentation follows the [Documentation style](CONTRIBUTING.md#documentation-style)
  section of CONTRIBUTING.md. Run its self-check before you commit prose.
- Run the test suite before and after a change, as CONTRIBUTING.md describes. If your
  sandbox cannot run it, say so in your report instead of a claim of success.
- Do not use the assistant's persistent memory for this project unless the user
  explicitly requires it. Create no memories, and rely on none. The committed tree is
  the source of truth: README.md, doc/, CONTRIBUTING.md, TODO.md, and git history.
  Memory rots as parallel sessions advance the repository, and stale memories have
  cost real work here more times than anyone counted.
