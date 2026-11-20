# Releasing katzenpost

A release is a tag `vX.Y.Z` on `main` whose commit has `X.Y.Z` as the top
entry of `debian/changelog`. The version is written nowhere else: the
.deb, Nix and Arch packages all read it from the changelog, and CI fails
a tag that does not match it.

## 1. Edit

On a branch off `main`:

- `debian/changelog`: add the new entry at the top, then run
  `make check-version tag=vX.Y.Z`.

  ```
  katzenpost (X.Y.Z) unstable; urgency=medium

    * Release X.Y.Z: <one-line summary>.

   -- Katzenpost <packages@katzenpost.network>  <output of date -Ru>
  ```

Only if kno's namenlos `client.toml`
(`data/networks/namenlos/.generated/configs/client.toml` in katzenpost/kno)
changed since the last release, pin the new kno commit. The .deb fetches
kno's `main` at build time and needs no edit.

- `flake.nix`: the commit in `clientToml`'s `url`, and its `hash`
  (`nix store prefetch-file <url>`).
- `packaging/arch/kpclientd/PKGBUILD`: `_kno` and `sha256sums`
  (`sha256sum client.toml`). Leave `pkgver` alone.
- `packaging/arch/kpclientd/.SRCINFO`: regenerate with
  `makepkg --printsrcinfo > .SRCINFO`.

Get the PR reviewed and merged.

## 2. Tag

```
git fetch origin
git tag -a vX.Y.Z origin/main -m vX.Y.Z
git push origin vX.Y.Z
```

A tag pushed without its changelog entry stays where it is. Add the entry
for the next version and tag that.

## 3. What CI publishes

`release.yml` creates the GitHub release, with the changelog entry as its
notes, and attaches:

- `kpclientd_X.Y.Z_amd64.deb` and `kpclientd_X.Y.Z_arm64.deb`
- `kpclientd-X.Y.Z-1-x86_64.pkg.tar.zst`
- `SHA256SUMS`

`nix run github:katzenpost/katzenpost/vX.Y.Z#kpclientd` works once the tag
exists. `deb.yml` and the docker mixnet tests also run on the tag; watch
them at https://github.com/katzenpost/katzenpost/actions.
