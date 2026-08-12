## GitHub grant: {arg} (write)

**Use git to clone, fetch, and push `{arg}`, and use the REST API for every other
GitHub operation — `gh` is not installed.** For issues, pull requests, releases, and
statuses, call `https://api.github.com/repos/{arg}/...` and send an `Authorization`
header with any value. The proxy replaces that value with the real credential. GraphQL
is not reachable. This grant includes API mutations: POST, PUT, PATCH, and DELETE.
