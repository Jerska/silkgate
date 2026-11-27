## GitHub grant: {arg} (read)

**Clone and fetch `{arg}` with git. Use the REST API for everything else: `gh` is not installed.**

- Call `https://api.github.com/repos/{arg}/...` with an `Authorization` header of any value.
  The proxy swaps in the real credential.
- This grant allows API GET only. Mutations need the github-write grant.
- GraphQL is not reachable.
