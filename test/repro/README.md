# Reproductions

Read this to re-run the demonstrations of the findings that seeded the test suite.

**These scripts print what they observed next to what they expected. They don't assert.**
The review behind them (`FEEDBACK.md`) lives in git history, and `test/` now covers each
finding. For example, `addon_host_spoof.py` became `test/test_addon.py`.

| Script | Finding | Needs |
|---|---|---|
| `engine_claims.py` | rule-engine parsing and matching defects | nothing |
| `addon_host_spoof.py` | critical: policy from a spoofable header, so a credential goes to the wrong host | mitmproxy |
| `build_injection.py` | shell and Dockerfile injection through `--with name@VERSION` and `--base` | nothing |
| `host_spoof_live.sh` | the same critical finding, end to end through a real proxy | mitmproxy, port 8099 |
| `connect_probe.sh` | `CONNECT` accepted with no policy decision and no audit line | mitmproxy, port 8099 |
| `git_profile_clone.sh` | `git` holds no rules, and `github` plus a `github-read` grant clone and fetch but never push | docker, msb, a built image |

None needs a real API key: `addon_host_spoof.py` leaks a sentinel, not a secret.

```sh
python3 test/repro/engine_claims.py
python3 test/repro/addon_host_spoof.py
python3 test/repro/build_injection.py
sh      test/repro/host_spoof_live.sh
sh      test/repro/connect_probe.sh
sh      test/repro/git_profile_clone.sh      # slowest: boots a guest
```
