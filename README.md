# nextstep-gh

A native GitHub CLI for NeXTSTEP 3.3 on Motorola 68040.

Connects directly to `api.github.com` over TLS 1.2 using [Crypto Ancienne](https://github.com/classilla/cryanc) by Cameron Kaiser. No proxy, no relay — real HTTPS from a 1991 NeXTstation pizzabox.

![NeXTSTEP 3.3](https://img.shields.io/badge/NeXTSTEP-3.3-black) ![m68k](https://img.shields.io/badge/arch-m68040-blue) ![TLS 1.2](https://img.shields.io/badge/TLS-1.2-green)

## Features

- Browse repositories, issues, and pull requests
- View file contents from any GitHub repo
- Create issues
- Pagination support
- Token-based authentication (personal access tokens)
- Pure C, no dependencies beyond the system compiler and Crypto Ancienne

## Building

### 1. Get Crypto Ancienne

On a modern machine with `curl` or `wget`:

```
./fetch_cryanc.sh
```

This downloads `cryanc.c` and `cryanc.h` from the [Crypto Ancienne repo](https://github.com/classilla/cryanc). They must be in the same directory as `gh.c`.

### 2. Transfer files to the NeXT

Get `gh.c`, `cryanc.c`, and `cryanc.h` onto the NeXTstation. FTP is the most reliable method — the NeXT has `/usr/ucb/ftp` built in.

### 3. Compile

On the NeXTstation:

```
cc -O -o gh gh.c
```

This takes ~10 minutes on a 25MHz 68040 — Crypto Ancienne is 1.4MB of crypto code compiled with optimization. You'll see warnings about integer constants and big endian — these are harmless.

## Setup

Create a GitHub personal access token at github.com/settings/tokens with `repo` scope, then:

```
echo 'ghp_xxxxxxxxxxxx' > .github_token
./gh
```

Or pass it directly:

```
./gh ghp_xxxxxxxxxxxx
```

## Usage

```
github> help

  Commands:
    repo owner/repo    Set default repo and show info
    repos [user]       List user's repos
    issues             List open issues
    issue N            View issue detail
    create "title" "body"  Create new issue
    pulls              List open pull requests
    cat path           View file contents
    next               Next page of results
    help               Show this help
    quit               Exit
```

## Example

```
github> repos ARNLTony
  ARNLTony/nextstep-gh (*0)
    A native GitHub CLI for NeXTSTEP 3.3

github> repo ARNLTony/nextstep-gh

  Repo: ARNLTony/nextstep-gh
  Lang: C
  Branch: main

github> cat README.md
```

## How it works

The program makes raw HTTPS connections to the GitHub REST API. TLS 1.2 is handled entirely in software by Crypto Ancienne, a TLS library designed for vintage and embedded systems. The JSON responses are parsed with a lightweight hand-written parser (no external JSON library needed).

Each API call involves:
1. DNS lookup for `api.github.com`
2. TCP connection to port 443
3. TLS 1.2 handshake (the slow part on a 68040)
4. HTTP/1.0 request with Bearer token auth
5. JSON response parsing and display

## Credits

- [Crypto Ancienne](https://github.com/classilla/cryanc) by Cameron Kaiser — the TLS library that makes this possible
- Built by ARNLTony & Claude

## License

MIT
# Built and tested on NeXTSTEP 3.3
