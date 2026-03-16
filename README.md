# nextstep-gh (Archived)

> **This project has been superseded by [nextstep-git](https://github.com/ARNLTony/nextstep-git)**, which now includes all GitHub CLI commands (issues, PRs, repos, file viewing) alongside full Git operations in a single binary.

---

A native GitHub CLI for NeXTSTEP 3.3 on Motorola 68040.

Connected directly to `api.github.com` over TLS 1.2 using [Crypto Ancienne](https://github.com/classilla/cryanc) by Cameron Kaiser. No proxy, no relay — real HTTPS from a 1991 NeXTstation pizzabox.

## Migration

All commands from this tool are available in [nextstep-git](https://github.com/ARNLTony/nextstep-git):

| nextstep-gh | nextstep-git |
|---|---|
| `repo owner/repo` | `git repo owner/repo` |
| `repos user` | `git repos user` |
| `issues` | `git issues` |
| `issue N` | `git issue N` |
| `create "title" "body"` | `git issue create "title" "body"` |
| `pulls` | `git pulls` |
| `cat path` | `git cat path` |

Plus nextstep-git adds: clone, push, pull, commit, branch, merge, tag, release, fork, rm, diff, compare, .gitignore support, and security hardening.

## Credits

- [Crypto Ancienne](https://github.com/classilla/cryanc) by Cameron Kaiser — the TLS library that makes this possible
- Built by ARNLTony & Claude

## License

MIT
