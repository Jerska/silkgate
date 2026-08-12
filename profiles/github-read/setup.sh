# The credential stub git spends against GitHub. The proxy's inject_auth=github rules
# replace the value of an Authorization header that is present, never add an absent
# one — so git must send one, and this is it. URL-scoped per host, never a bare
# http.extraHeader: git-lfs applies a global header to every request, including the
# github-cloud.s3.amazonaws.com upload that carries its own AWS SigV4 Authorization,
# and a second Authorization header there makes S3 answer 501. One canonical
# overwrite, byte-identical in github-read and github-write, so any mix of the two
# profiles in one image writes the same file. git is not needed at build time.
set -eu
printf '[http "https://%s/"]\n\textraHeader = Authorization: Basic c2lsa2dhdGU=\n' \
    github.com lfs.github.com api.github.com > /root/.gitconfig
