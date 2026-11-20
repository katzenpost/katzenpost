# Releasing katzenpost

A release is a git tag `vX.Y.Z` on `main` whose commit has `X.Y.Z` as the
top entry of `debian/changelog`. That entry is the only place the version
is written: the Makefile takes it from `git describe --tags`, and
`debian/rules`, `flake.nix` and the Arch `PKGBUILD` (its `pkgver()`) read
it from the changelog. CI checks the pairing with `make check-version`: a
tag build fails unless the changelog version equals the tag, and any other
build fails if the changelog is older than the newest reachable tag.

## Steps

1. On a branch off the latest `main`, add the new entry at the top of
   `debian/changelog`:

   ```
   katzenpost (X.Y.Z) unstable; urgency=medium

     * Release X.Y.Z: <one-line summary of what changed>.

    -- Katzenpost <packages@katzenpost.network>  <output of date -Ru>
   ```

   Check it with `make check-version tag=vX.Y.Z`.

2. If kno's namenlos `client.toml`
   (`data/networks/namenlos/.generated/configs/client.toml` in
   katzenpost/kno) changed since the last release, point the Nix and Arch
   packages at the new kno commit. The .deb fetches kno's `main` at build
   time and needs nothing.
   - `flake.nix`: the commit in `clientToml`'s `url`, and its `hash`
     (`nix store prefetch-file <url>` prints it).
   - `packaging/arch/kpclientd/PKGBUILD`: `_kno` (same commit) and
     `sha256sums` (`sha256sum client.toml`), then regenerate `.SRCINFO`
     with `makepkg --printsrcinfo > .SRCINFO` in that directory.

   The `pkgver` written in the PKGBUILD and `.SRCINFO` needs no bump:
   makepkg replaces it from the changelog on every build.

3. Open a PR with these changes, alone or as the last commit of the PR
   being released, and get it reviewed and merged.

4. Tag the merge commit on `main` and push the tag:

   ```
   git fetch origin
   git tag -a vX.Y.Z origin/main -m vX.Y.Z
   git push origin vX.Y.Z
   ```

5. The tag push runs `deb.yml` (version check, katzenpost .deb) and the
   docker mixnet tests. `release.yml` creates the GitHub release for the
   tag, with the top changelog entry as its notes, and attaches:
   - `kpclientd_X.Y.Z_amd64.deb` and `kpclientd_X.Y.Z_arm64.deb`
     (`make deb-kpclientd`);
   - `kpclientd-X.Y.Z-1-x86_64.pkg.tar.zst` (the Arch PKGBUILD);
   - `SHA256SUMS` covering all of them.

   `nix run github:katzenpost/katzenpost/vX.Y.Z#kpclientd` works once the
   tag exists. `interop-releases.yml` tests the two newest tags nightly.
   Watch the runs at https://github.com/katzenpost/katzenpost/actions.

A tag pushed without its changelog entry is not moved or re-tagged: add
the entry for the next version and tag that instead.
