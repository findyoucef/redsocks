# Packages and releases

The **Packages and releases** workflow builds macOS arm64, macOS x86_64, and
Linux x86_64 packages. Every target provides a `.tar.gz` archive and a native
installer: `.pkg` on macOS, `.deb` on Linux. Source, notices, example
configurations and build metadata are included. Libevent is linked statically;
there is no runtime dependency on Homebrew or a separately installed libevent.

macOS packages target macOS 15 or newer. They are ad-hoc code-signed for local
execution, but their installers are unsigned and are not Apple-notarized.
Linux packages target Ubuntu 24.04+ (glibc 2.39+). Other Linux distributions
may use the archive if compatible; RPM and ARM Linux packages are not built.

## Install

Download the matching asset and `SHA256SUMS` from GitHub Releases. Verify the
selected filename against the checksum before installation, for example:

```sh
shasum -a 256 redsocks-0.6.0-macos-arm64.pkg
# Compare with that filename's entry in SHA256SUMS.
sudo installer -pkg redsocks-0.6.0-macos-arm64.pkg -target /
```

macOS installs `/usr/local/sbin/redsocks` and documentation under
`/usr/local/share/doc/redsocks`. For Linux:

```sh
sudo apt install ./redsocks-0.6.0-linux-x86_64.deb
```

The Debian package installs `/usr/sbin/redsocks` and `/usr/share/doc/redsocks`.
The package name is `redsocks`, so installing it replaces an existing package
of that name. Archives can instead be extracted and their `sbin/redsocks`
executed directly. Installation does not enable a service, install live
configuration, or alter PF/iptables rules. Follow the included macOS guide or
Linux examples to configure interception and an upstream proxy.

## Publish a version

After merging and testing a release commit on `main`:

```sh
git switch main
git pull --ff-only
git tag -a v0.6.0 -m 'redsocks 0.6.0'
git push origin v0.6.0
```

Use a new `vMAJOR.MINOR.PATCH` tag for each release. Tags pointing outside
`main` are rejected by the publishing job. Every package must pass regression
tests, dependency checks, extraction checks, and installation tests first.
The macOS jobs additionally run the privileged PF/utun interception tests.
Only the publishing job gets `contents: write`; no personal access token or
other repository secret is required. It creates a draft, uploads the complete
asset set and SHA-256 manifest, then publishes it. A failed upload leaves a
draft that the same run can resume. Published assets cannot be overwritten by
this workflow; use a new version.

Ordinary pushes to main, pull requests and manual workflow runs build preview
packages with version `0.0.0` and retain their artifacts for 14 days. They do
not create a GitHub Release. Download them from the workflow run's Artifacts
section. These previews are for validation, not upgrades of installed releases.

To reproduce a package locally, install Python 3.12+, the native build tools,
and libevent development files, then run from a clean commit:

```sh
python3 packaging/build.py 0.6.0
```

Results go into `dist/<platform>-<architecture>/`, which must be empty at the
start. `packaging/verify.py` installs packages and is intended for disposable
CI runners. `packaging/build.py` does not install them. The included source
archive contains all redsocks build inputs; libevent's license notices are
included separately alongside the project's source-file notices.
