# arngory/yggdrasil-go

A fork of [yggdrasil-network/yggdrasil-go](https://github.com/yggdrasil-network/yggdrasil-go) for
[Niko](https://github.com/arngory/niko) and [niko-server](https://github.com/arngory/niko-server). Our branch is
**`niko`**: upstream **v0.5.15** (`2c7f050`) and the changes below. Each is off unless the embedding program
asks for it, so for anyone else the fork behaves as upstream. Upstream's branches (`develop`, `master` and the rest) are
kept as upstream has them.

## What differs from upstream

| Change | Why | Where | Tests |
|---|---|---|---|
| `LinkDialer` setup option: `DialContext`, `ListenPacket`, `TLSClient` | the program opens the outgoing peering connections itself: Niko routes them around the VPN it provides, through its own DNS and dialer, with a browser ClientHello for `tls://` | `src/core/options.go`, `link*.go` | `src/core/link_dialer_test.go` |
| `DebugPrivacy` setup option | a server whose peers are its users' devices leaves remote `getSelf`, `getPeers` and `getTree` unanswered: `getPeers` lists the key of every connected device | `src/core/options.go`, `core.go`, `proto.go` | `src/core/debugprivacy_test.go` |
| `PQSessions` setup option | ironwood's hybrid post-quantum sessions (arngory/ironwood, Niko's `docs/design/ironwood-pq.md`): classic with nodes without them, PQ between two that have them, `Required` keys refuse classic | `src/core/options.go`, `core.go`; ironwood pinned to arngory/ironwood in `go.mod` | `src/core/pq_test.go` |
| ipv6rwc: Packet Too Big only to a checked source | an oversize packet got an ICMPv6 Packet Too Big, with up to 512 of its bytes, before its source was checked against the sender's key: one client could have the server send another client its bytes | `src/ipv6rwc/ipv6rwc.go` | `src/ipv6rwc/ptb_test.go` |

### Turning `PQSessions` off again

A node that had PQ sessions with a peer holds that peer to PQ until the end (notAfter) of the peer's newest ML-KEM
key, at most 48 hours, refusing classic from it meanwhile: a downgrade is not something an attacker can force. So a
node that turns `PQSessions` off, or a release that drops it, reaches its PQ peers again only once their hold on it ends
(up to 48 hours), unless they restart. While the option is off the node answers a PQ packet from a key it has no
session with by a classic init (ironwood), and a PQ peer whose PQ session stays silent drops it by itself: peers that do
not hold the node to PQ come back to classic at once.

## Who pins it

| Where | Pin |
|---|---|
| niko-server `go.mod` | `replace github.com/yggdrasil-network/yggdrasil-go => github.com/arngory/yggdrasil-go v0.5.16-0.20261108201637-5afe92f15200` |
| Niko `libcore/go.mod` | the same commit |

A pin names a commit, so `niko` can move on and the pinned commit stays in its history. `niko` is never rewritten (no
rebase, no force-push): a pin on a commit that is gone no longer builds.

## Working on it

- A change goes to `niko` by a pull request from a branch of its own, with a test that fails without it.
- A new upstream version comes in by a merge of its tag into `niko` (`git merge v0.5.16`), in a pull request: the
  tests above and `go test ./...` pass before it is merged. Then the pins move, in their own repositories.
- Checks (`.github/workflows/checks.yml`): "Commit messages" (no bare `#N`; in a fork GitHub links a bare `#N` to
  upstream's issues, so write `arngory/yggdrasil-go#N`) and "Secrets" (gitleaks, rules in `.gitleaks.toml`). Upstream's
  commits brought in by a merge are upstream's: the checks take only the pull request's own line. Upstream's CI
  (`ci.yml` and the rest) runs as upstream has it.
- A pull request that changes the checks themselves is merged by the owner.
- The rules shared with raycontrol, niko-server and Niko: raycontrol's
  [CONTRIBUTING.md](https://github.com/arngory/raycontrol/blob/main/CONTRIBUTING.md).
