# Ideas & Future Improvements

## SOCKS proxy for non-HTTP traffic

**Problem:** Currently non-HTTP is blocked entirely. Some use cases need SSH, git://, or other protocols but with domain restrictions.

**Solution:** Add a SOCKS proxy (like `redsocks` + `dante` or a custom Go proxy) that:
- Intercepts all non-HTTP TCP via iptables redirect
- Sees the destination domain (via SOCKS5 CONNECT)
- Applies domain-based filtering similar to HTTP policy

**DSL extension:**
```
# In policy.txt
github.com:
  allow GET /repos/**
  allow ssh          # New: allow SSH (port 22) to this domain

git.example.com:
  allow git          # New: allow git:// protocol (port 9418)
```

**Implementation:**
1. Run SOCKS proxy on host, listening on a port
2. Redirect non-HTTP TCP to SOCKS proxy via iptables REDIRECT
3. SOCKS proxy reads policy.txt, filters by domain + port
4. Allowed connections are forwarded, others rejected

---

## DNS-tracking firewall

**Alternative to SOCKS:** Track DNS resolutions to build IP→domain mappings, then apply iptables rules dynamically.

**Pros:** No proxy overhead for allowed connections
**Cons:** Complex, race conditions between DNS response and connection

---

## macOS support

Network namespaces don't exist on macOS. Options:
- Run Linux VM (Lima, Orbstack) with namespace setup inside
- Use Network Extension API (complex, requires signing)
- PF + per-user routing (weaker isolation)

---

## Host port exposure

Allow sandbox to reach specific ports on host's localhost:
```bash
sudo ./sandbox.sh --expose 3000 --expose 5432
```

Would add DNAT rules to forward those ports.

---

## Policy hot-reload

Reload policy.txt without restarting the proxy. Could use:
- File watcher (inotify)
- SIGHUP handler
- HTTP endpoint on proxy
