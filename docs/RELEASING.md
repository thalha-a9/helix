# Releasing Helix

A release is one tag. Pushing `vX.Y.Z` runs `.github/workflows/release.yml`:
it checks the tag matches `osint/__init__.py`, builds, tests the built
package, publishes to PyPI and creates the GitHub release with the
changelog section as notes.

## One-time setup (helix repository)

1. **PyPI Trusted Publishing**: no token to leak.
   On <https://pypi.org/manage/project/helix-osint/settings/publishing/>
   add a GitHub publisher:
   - Owner: `thalha-a9`
   - Repository: `helix`
   - Workflow: `release.yml`
   - Environment: `pypi`
2. **GitHub environment**: repository Settings -> Environments -> New
   environment -> `pypi`. Optionally require your own approval before each
   publish.

## Each release

1. Set the version in `osint/__init__.py` and add a `## vX.Y.Z (date)`
   section at the top of `CHANGELOG.md` (a test fails if it is missing).
2. Merge to `main` with CI green.
3. Tag and push:

   ```bash
   git checkout main && git pull
   git tag -a v3.5.0 -m "Helix v3.5.0"
   git push origin v3.5.0
   ```

4. Watch the **Release** workflow. When it is green:
   - <https://pypi.org/project/helix-osint/> shows the new version,
   - the GitHub release has the wheel, the sdist and the notes.

## After the release

- **BlackArch:** open a pull request adding `packages/helix-osint/PKGBUILD`
  to github.com/BlackArch/blackarch, from `packaging/blackarch/PKGBUILD`.
  Run `updpkgsums` first so the checksum is real.
- **Kali:** file a New Tool Request on bugs.kali.org.

`updpkgsums` comes with Arch's `pacman-contrib`. Without an Arch machine:

```bash
curl -sL https://files.pythonhosted.org/packages/source/h/helix-osint/helix_osint-3.5.0.tar.gz | sha512sum
```

and paste the hash into `sha512sums=(...)`.
