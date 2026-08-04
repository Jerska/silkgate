#!/bin/sh
# `--with git` installs git and a ruleset that cannot clone from GitHub.
#
# git's smart-HTTP clone is GET /org/repo/info/refs?service=git-upload-pack followed by
# POST /org/repo/git-upload-pack. The profile's rules declare neither `q:` (so every query
# parameter is stripped, and GitHub answers the resulting dumb-http request with 403) nor POST
# with a body (so phase two is denied twice over).
#
# Observed: "GitHub.com no longer supports git over dumb-http ... error: 403".
#
# The guest sees GitHub's own 403, which the generated sandbox brief teaches it to read as
# silkgate policy — so the failure is also misattributed.
#
#     sh test/repro/git_profile_clone.sh
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)

"$REPO/cli/silkgate" run \
    --with git \
    -- sh -c 'git clone --depth 1 https://github.com/octocat/Hello-World /tmp/hw 2>&1 | tail -3'

echo
echo 'A working ruleset needs the query parameter and the POST, roughly:'
echo "  github.com/*/*/info/refs      GET  q:service~git-(upload|receive)-pack"
echo "  github.com/*/*/git-upload-pack POST max_body=1m h:content-type=application/x-git-upload-pack-request"
echo 'Keep push denied — that part of the profile comment is right.'
