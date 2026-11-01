# Releasing katzenpost

A release is a git tag `vX.Y.Z` on `main` whose commit has `X.Y.Z` as the
top entry of `debian/changelog`. Nothing else carries the version: binaries
get it from `git describe --tags` (Makefile) or from the changelog
(`debian/rules`).

CI enforces the pairing with `make check-version` (`deb.yml`):

- a tag build fails unless the top changelog version equals the tag;
- every other build fails if the top changelog version is older than the
  newest tag reachable from the commit.

So the changelog entry is merged first and the tag pushed afterwards.

## Steps

1. On a branch off the latest `main`, add the entry at the top of
   `debian/changelog`, with a one-line summary of what changed:

   ```
   katzenpost (X.Y.Z) unstable; urgency=medium

     * Release X.Y.Z: <summary>.

    -- Katzenpost <packages@katzenpost.network>  <output of date -Ru>
   ```

   Check it with `make check-version tag=vX.Y.Z`.

2. Open a PR with that commit, alone or as the last commit of the PR being
   released, and get it reviewed and merged.

3. Tag the merge commit on `main` and push the tag:

   ```
   git fetch origin
   git tag -a vX.Y.Z origin/main -m vX.Y.Z
   git push origin vX.Y.Z
   ```

4. The tag push runs the version check in `deb.yml` and the docker mixnet
   integration tests; `interop-releases.yml` tests the two newest tags
   nightly. Watch them at https://github.com/katzenpost/katzenpost/actions.

A tag pushed without its changelog entry is not moved or re-tagged: add the
entry for the next version and tag that instead.
