# ADR-011: Deny container-engine and agent sockets for every app

**Status**: Accepted

**Date**: 2026-11-02

## Context

Shentu found that an app with its home folder closed off could still reach Docker's socket (and mount home in a container) or ssh-agent's (and sign as you). Connecting to a Unix-domain socket is `network-outbound`, not a file access, so file protections like `~/.ssh` and `~/.docker` never applied, and "network off" only denies `(remote ip)`.

Menshen starts from `(deny default)`, so an app can't reach a socket it never used while learning. But a connect seen during learning became an ordinary learned allow, with nothing to flag it.

## Decision

Hardening gets socket entries (`Hardening.sockets`), each a regex on the socket's full path, compiled as `(deny network-outbound (regex #"…"))` in the hardening section, after learned and your rules:

- `H-sock-containers`: `docker`, `podman`, `containerd`, `colima`, `orbstack` `*.sock` (also Rancher's `~/.rd/docker.sock` and Lima's)
- `H-sock-ssh-agent`: launchd's ssh-agent (`/private/tmp/com.apple.launchd.*/Listeners`) and OpenSSH's own (`/tmp/ssh-*/agent.N`)
- `H-sock-agents`: `agent.sock` (1Password), `socket.ssh` (Secretive), `S.gpg-agent*`

Learning sees connects, so a matching connect is a hit (FLAGGED, not learned), like a protected file. A new filter kind, `socket-pattern`, only accepts Menshen's own patterns, checked on load like `home-pattern`; an older built-in pattern is updated. Existing configs get the entries through `withCurrentProtections`.

## Rationale

Shentu closes every Unix socket but syslog and DNS, because it has no learned rules to go on. Menshen does, so a deny list of known escape sockets keeps everything else an app learned working.

## Consequences

- An app that really uses one of these (a Docker GUI, a Git client signing commits through an agent) is blocked until you set that protection to allow for it.
- A socket at an unlisted path isn't covered. The list is by name: a container engine or agent listening somewhere else needs a new entry.
- `IntegrationTests.escapeSocketsAreDenied` checks against the real kernel: a learned socket still works, a learned Docker or ssh-agent socket is blocked, and switching the entry to allow re-opens it.

## Alternatives Considered

- Deny every Unix socket but syslog and DNS (Shentu's rule): breaks learned local IPC that is fine.
- A file-style subpath deny on `~/.docker`: doesn't apply to `network-outbound`, and misses `/var/run/docker.sock` and agents in `/tmp`.
