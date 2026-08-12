# Reproductions from the retired review

Each script here demonstrates one finding from the review that seeded the test suite
(`FEEDBACK.md`, kept in git history) and prints what it observed next to what it expected, so
it can be turned into an assertion. They were written when the enforcement code had no tests;
the suite in `test/` covers it now, and TODO.md carries the review's still-open items.

**These are reproductions, not a test suite.** They print; they do not assert.
`addon_host_spoof.py` did become `test/test_addon.py` — `tflow`-based cases run in CI — so the
finding it demonstrates can never regress.

| script | finding | needs |
|---|---|---|
| `engine_claims.py` | rule-engine parsing and matching defects | nothing (stdlib) |
| `addon_host_spoof.py` | **critical**: policy from a spoofable header, credential injected to the wrong host | `pip install mitmproxy` |
| `build_injection.py` | shell/Dockerfile injection through `--with name@VERSION` and `--base` | nothing |
| `host_spoof_live.sh` | the same critical finding end to end, through a real proxy | mitmproxy; binds :8099 |
| `connect_probe.sh` | `CONNECT` is accepted with no policy decision and no audit line | mitmproxy; binds :8099 |
| `git_profile_clone.sh` | the git profile holds zero rules, and the github floor plus a github-read grant clone and fetch, never push | docker, msb, a built image |

No script here needs a real API key: `addon_host_spoof.py` uses a sentinel secret so that what
leaks in the demonstration is a string with no value.

```sh
python3 test/repro/engine_claims.py
python3 test/repro/addon_host_spoof.py
python3 test/repro/build_injection.py
sh      test/repro/host_spoof_live.sh
sh      test/repro/connect_probe.sh
sh      test/repro/git_profile_clone.sh      # slowest; boots a guest
```
