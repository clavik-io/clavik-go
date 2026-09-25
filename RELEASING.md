# Releasing clavik-go

Releases are automatic. Merge to `main` and the version, the tag and the
release notes follow from the commits. **Do not create tags by hand.**

## How a release happens

Every push to `main` runs `.github/workflows/ci.yml`:

1. **test**: `go vet` and `go test -race`, on the Go version in `go.mod` and
   on the latest stable Go. It also checks `gofmt` and builds `example/`.
2. **release**, only if `test` passed:
   [semantic-release](https://github.com/semantic-release/semantic-release)
   reads the commits since the last tag and decides the next version. It then
   pushes the tag `vX.Y.Z` and creates a
   [GitHub release](https://github.com/clavik-io/clavik-go/releases) whose
   notes are generated from those commits.
3. The new version is requested from `proxy.golang.org`, so it can be
   installed straight away and appears on pkg.go.dev without waiting for a
   first user.

For a Go module the tag *is* the release. There is nothing to build or upload.

## How the version is decided

semantic-release takes the largest bump any commit since the last tag asks
for ([Conventional Commits](https://www.conventionalcommits.org/)):

| Commit | Example | Release |
| --- | --- | --- |
| `feat` | `feat(secrets): add Secrets.Copy (#12)` | **minor**, 1.2.0 → 1.3.0 |
| `fix`, `perf` | `fix(keys): report a valid signature as Valid (#1)` | **patch**, 1.2.0 → 1.2.1 |
| `!` after the type, or a `BREAKING CHANGE:` footer | `feat(client)!: drop WithBaseURL (#20)` | **major**, see below |
| `docs`, `test`, `ci`, `chore`, `refactor`, `build`, `style` | `docs(readme): fix example` | none |

A push that contains only non-releasing commits produces no release. The job
still passes.

**The commit type is a release decision.** A change a caller can notice is a
`fix` or a `feat`, never a `chore` or a `refactor`. Otherwise it does not ship
until something else triggers a release.

**Breaking the API means a new major version, and for Go that also means a new
import path.** Renaming or removing an exported identifier, changing a
signature, or changing documented behaviour breaks callers. From v2 onward the
module path must end in `/v2`, so a major release also needs `go.mod` and every
import updated in the same change. Go will not resolve a `v2.0.0` tag on a
module path without `/v2`.

Every commit on `main` counts, including each commit of a merged pull request,
not only its title. If a branch's history does not describe what should be
released, squash-merge it and give it a conventional title.

## Why tags must not be made by hand

The Go module proxy caches every version it is shown, **permanently**. A tag
that was a mistake cannot be withdrawn once anyone has fetched it; the most
that can be done is a `retract` directive in `go.mod` in a later release.
semantic-release only ever tags a commit that passed the tests, with the next
version in sequence.

It is also safe to re-run: the release job announces to the proxy only a tag
that it created in the same run, never one that was already on the commit.

## Setup

Nothing to configure. The job uses the workflow's built-in `GITHUB_TOKEN`
with `contents: write`, and no secrets. A tag pushed with that token does not
trigger further workflows. Nothing here needs it to.

Release comments on issues and pull requests, and "released" labels, are
turned off in `.releaserc.json`, so the job needs no permissions beyond
`contents: write`.

## Verifying a release

```bash
gh release view vX.Y.Z --repo clavik-io/clavik-go
curl -s https://proxy.golang.org/github.com/clavik-io/clavik-go/@v/list
go list -m github.com/clavik-io/clavik-go@latest
```

## Pinned versions

The actions are pinned by commit SHA and the npm packages by exact version:
`semantic-release@25.0.9` and `conventional-changelog-conventionalcommits@9.3.1`.
semantic-release's own plugins resolve within the ranges that version
declares. Upgrade deliberately, and let the next release prove it.

The preset and semantic-release have to be upgraded together.
`conventional-changelog-conventionalcommits` 10.x renders only with
`conventional-changelog-writer` 9. semantic-release 25.0.9 ships
`@semantic-release/release-notes-generator` 14, which loads writer 8, so a 10.x
preset fails at "generateNotes" before anything is tagged. This is what failed
the first release run.

To test an upgrade locally, run a dry run with the real `.releaserc.json`.
Do not override plugins with `--plugins`: that drops the preset options and
tests the default preset instead.
