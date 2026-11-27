## GitHub grant: {arg} (write)

**Clone, fetch, and push `{arg}` with git. Use the REST API for everything else: `gh` is not installed.**

- Call `https://api.github.com/repos/{arg}/...` with an `Authorization` header of any value.
  The proxy swaps in the real credential.
- This grant allows API mutations: POST, PUT, PATCH, DELETE.
- GraphQL is not reachable.
