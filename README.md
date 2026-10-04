# ylluminate-blocklist

A small personal network blocklist: domains and IPv4 ranges, kept as two plain
source files and compiled into the formats common blocking tools read.

## Source lists

- `lists/domains.txt` - one domain per line. Blank lines and `#` comments are
  allowed, and an entry may carry a trailing `# note`.
- `lists/ips.txt` - one entry per line: a single IPv4 address (`1.2.3.4`), a
  CIDR (`10.0.0.0/8`), or an inclusive range (`1.2.3.4-1.2.3.255`). Each may be
  followed by `# description`.

## Generated files (`dist/`)

| File | Format | Use with |
|------|--------|----------|
| `hosts.txt` | `0.0.0.0 domain` hosts file | AdAway, `/etc/hosts`, Pi-hole |
| `domains.txt` | plain domain list | resolvers and scripts that take a bare list |
| `adblock.txt` | `\|\|domain^` Adblock syntax | uBlock Origin, AdGuard |
| `ipfilter.dat` | eMule / PeerGuardian DAT, zero-padded ranges | BitTorrent clients, PeerBlock |
| `p2p.txt` | PeerGuardian P2P text, `description:start-end` | clients that read P2P lists |
| `blocklist.lsrules` | Little Snitch rule group (JSON) | Little Snitch (`denied-remote-domains`) |

## Adding an entry

1. Edit `lists/domains.txt` or `lists/ips.txt`.
2. Run `make` (alias for `make build`). Invalid entries are rejected with the
   file and line number.
3. Run `make test` if you changed `build.py`.
4. Commit the source lists and the regenerated `dist/` files together.

The build needs only Python 3 and the standard library. Output is sorted and
de-duplicated, and is deterministic apart from the date in the headers; set
`SOURCE_DATE_EPOCH` to pin it.

## Raw URLs

Consume the generated files directly:

```
https://raw.githubusercontent.com/ylluminate/ylluminate-blocklist/main/dist/<file>
```

For example `.../dist/hosts.txt` or `.../dist/ipfilter.dat`.

## License

CC0 1.0 Universal (public domain dedication). See `LICENSE`.
