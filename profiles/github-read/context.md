## GitHub grant: {arg} (read)

**Use git to clone and fetch `{arg}`, and use the REST API for every other GitHub
operation — `gh` is not installed.** For issues, pull requests, releases, and statuses,
call `https://api.github.com/repos/{arg}/...` and send an `Authorization` header with
any value. The proxy replaces that value with the real credential. GraphQL is not
reachable. This grant admits API GET alone. Mutations need the github-write grant.
