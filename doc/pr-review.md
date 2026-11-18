# Upstream PR integration

Base: darkk/redsocks `19b822e345f6a291f6cff6b168f1cfdfeeb2cd7d`.
Initial triage: 2026-11-18. These decisions concern a focused IPv4 TCP macOS
port, not wholesale acceptance of every change on the contributors' branches.

## Selected changes

| PR | Author | Disposition |
| --- | --- | --- |
| [123](https://github.com/darkk/redsocks/pull/123) | @apoikos | Adapted public libevent version detection; avoids the wrong line reader with libevent 2.1. |
| [95](https://github.com/darkk/redsocks/pull/95) | @apoikos | Adapted compile-time splice guards, buffer fallback, keepalive guards, PF target and list macro fixes. |
| [100](https://github.com/darkk/redsocks/pull/100) | @agusdallalba | Adapted the final listener recovery change, including the follow-up that avoids enabling during continuing pressure. |
| [50](https://github.com/darkk/redsocks/pull/50) | @luizluca | Adapted group clearing and added a fatal error check; original ignored failure. |
| [164](https://github.com/darkk/redsocks/pull/164) | @adrelanos | Applied consistent example credential quoting. |
| [105](https://github.com/darkk/redsocks/pull/105) | @a7ypically | Incorporated compiler-target detection and selected compiler use into the macOS build changes. Dependency generation now also receives the actual build flags. |

The selected changes are reconstructed/adapted from the reviewed diffs, with
source attribution in commit messages. They are not literal cherry-picks or
merges of the complete upstream PR branches. The `curated-fixes` branch preserves the selected fixes before the macOS
changes on `main`. The selected fixes pass the portable regression suite on Linux before the
macOS changes, and the port passes it on macOS. See
[macos.md](macos.md#verification) for coverage and the pending privileged PF test.

## Deferred or rejected from this baseline

| PR | Decision |
| --- | --- |
| [151](https://github.com/darkk/redsocks/pull/151) | Defer. Extract the auth fix separately from unrelated packaging/version changes. Its original implementation searches Basic/Digest substrings anywhere in the header, rather than validating the challenge scheme. |
| [153](https://github.com/darkk/redsocks/pull/153/files) | Rework. `0x50` still has two bits set despite the stated one-bit intent. |
| [175](https://github.com/darkk/redsocks/pull/175/files) | Reject as a functional fix: changes a placeholder string to another of the same length. |
| [143](https://github.com/darkk/redsocks/pull/143) | Defer Linux netfilter naming/nftables documentation; unrelated to macOS interception. |
| [162](https://github.com/darkk/redsocks/pull/162), [71](https://github.com/darkk/redsocks/pull/71) | Defer overlapping hostname/SNI parsing features and parser dependencies until baseline forwarding is validated. |
| [102](https://github.com/darkk/redsocks/pull/102) | Defer hostname cache proof of concept; not required for the port. |
| [83](https://github.com/darkk/redsocks/pull/83) | Defer SOCKS4 source disclosure feature; not required for the port. |
| [55](https://github.com/darkk/redsocks/pull/55) | Do not merge the branch wholesale: the ACL PR includes much broader redsocks2/encryption changes. |
| [54](https://github.com/darkk/redsocks/pull/54) | Defer configurable relay timeouts; old code context needs rebasing and behavioral tests. |
| [53](https://github.com/darkk/redsocks/pull/53) | Defer legacy HTTP relay changes. The upstream README already documents known security limitations in that module; use HTTP CONNECT instead. |
| [51](https://github.com/darkk/redsocks/pull/51) | Reject from this baseline: removes C99 loop declarations and compiler flags unnecessarily for current Clang/GCC. |
| [106](https://github.com/darkk/redsocks/pull/106) | Defer Android-specific changes, including unrelated version-definition changes. |
