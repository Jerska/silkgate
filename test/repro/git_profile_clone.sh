#!/bin/sh
# The git profile is tooling-only, and GitHub egress is a separate grant: `--with git`
# alone reaches nothing, `--with github` is the anonymous public-read floor, and
# `--with github-read:OWNER/REPO` layers a credentialed grant over it. First-match-wins
# plus composition order (arg-instance expansions before no-arg floors) means the grant
# must govern every smart-HTTP leg of the granted repo.
#
# git's smart-HTTP fetch is GET /org/repo/info/refs?service=git-upload-pack followed by
# POST /org/repo/git-upload-pack; a push is the same pair with git-receive-pack. So the
# composed policy has to preserve the service query param and allow the POST body, while
# keeping git-receive-pack unreachable both as a q: value and as a path.
#
# Two checks:
#   1. Static (runs anywhere with python3): profiles/git/rules.txt parses to zero rules,
#      and the composed github floor plus a github-read grant matches both fetch phases
#      with the credential and denies push.
#   2. Live (needs the host: msb + mitmproxy): a real clone, fetch, and push attempt
#      through a session running --with git --with github. The push must fail; note that
#      it fails with GitHub's own dumb-http 403 (the proxy strips
#      ?service=git-receive-pack), which the guest can misread as silkgate policy — a
#      known documentation gap, not a leak.
#
#     sh test/repro/git_profile_clone.sh            # both checks; needs the host
#     sh test/repro/git_profile_clone.sh --static   # check 1 only; python3 is enough
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)

python3 - "$REPO" <<'EOF' || exit 1
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "mitmaddon"))
from rule_engine import RuleSet

fails = 0


def check(label, ok):
    global fails
    fails += 0 if ok else 1
    print(f"{'  ' if ok else '!!'} {label}")


# the git profile itself: tooling only, zero rules
git_rules = RuleSet.parse((repo / "profiles/git/rules.txt").read_text())
check("git profile parses to zero rules", git_rules.rules == [])

# a granted session's composed policy: the github-read grant (an arg-instance
# expansion) before the github floor, which is compose_rules' order
grant = (repo / "profiles/github-read/rules.txt").read_text().replace(
    "{arg}", "octocat/Hello-World")
floor = (repo / "profiles/github/rules.txt").read_text()
rs = RuleSet.parse(grant + "\n" + floor)

# fetch phase 1: ref advertisement, with the service param intact and the credential
adv = rs.match("github.com", "/octocat/Hello-World/info/refs", "GET", 443)
check("GET info/refs matches", adv is not None)
check("the github-read grant governs it (inject_auth=github)",
      adv is not None and adv.inject_auth == "github")
check("q: service=git-upload-pack preserved",
      adv is not None and adv.query_ok("service", "git-upload-pack"))
check("q: service=git-receive-pack stripped (a push cannot start)",
      adv is not None and not adv.query_ok("service", "git-receive-pack"))
check("git-protocol header forwarded on GET",
      adv is not None and adv.header_ok("git-protocol", "version=2"))
gitform = rs.match("github.com", "/octocat/Hello-World.git/info/refs", "GET", 443)
check(".git-suffixed path matches with the credential",
      gitform is not None and gitform.inject_auth == "github")

# fetch phase 2: pack negotiation
up = rs.match("github.com", "/octocat/Hello-World/git-upload-pack", "POST", 443)
check("POST git-upload-pack matches", up is not None)
check("the grant governs it (inject_auth=github)",
      up is not None and up.inject_auth == "github")
check("negotiation body allowed (max_body=1m)",
      up is not None and up.max_body == 1024 * 1024)
check("content-type forwarded",
      up is not None and up.header_ok("content-type", "application/x-git-upload-pack-request"))
check("accept forwarded",
      up is not None and up.header_ok("accept", "application/x-git-upload-pack-result"))
check("git-protocol header forwarded on POST",
      up is not None and up.header_ok("git-protocol", "version=2"))

# push: unreachable as a path, in either method
check("POST git-receive-pack denied",
      rs.match("github.com", "/octocat/Hello-World/git-receive-pack", "POST", 443) is None)
check("GET git-receive-pack denied",
      rs.match("github.com", "/octocat/Hello-World/git-receive-pack", "GET", 443) is None)

# an ungranted repo falls through to the anonymous floor
other = rs.match("github.com", "/octocat/Spoon-Knife/info/refs", "GET", 443)
check("an ungranted repo falls through to the floor, without the credential",
      other is not None and other.inject_auth is None)

# still-declared companions of the floor
check("raw.githubusercontent.com GET allowed",
      rs.match("raw.githubusercontent.com", "/octocat/Hello-World/master/README", "GET", 443) is not None)
check("codeload.github.com GET allowed",
      rs.match("codeload.github.com", "/octocat/Hello-World/tar.gz/master", "GET", 443) is not None)

print("static rule checks:", "ok" if not fails else f"{fails} FAILED")
sys.exit(1 if fails else 0)
EOF

# `--static` is the rule checks alone: everything below needs msb, docker and the network,
# which is what keeps the full script out of the host test suite.
[ "${1:-}" = "--static" ] && exit 0

# Live check — host only, over the anonymous public floor: clone and fetch must succeed
# with no credential; the push attempt must fail before it can transfer anything (its
# ref advertisement never reaches GitHub intact).
"$REPO/cli/silkgate" run \
    --with git \
    --with github \
    -- sh -c 'set -e
        git clone --depth 1 https://github.com/octocat/Hello-World /tmp/hw
        git -C /tmp/hw fetch --depth 2
        echo CLONE-AND-FETCH-OK
        ! GIT_TERMINAL_PROMPT=0 git -C /tmp/hw push origin HEAD:refs/heads/silkgate-push-probe
        echo PUSH-DENIED-OK'
