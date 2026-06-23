# Release Management

How to create, update, and manage Wardex releases on GitHub.

## Prerequisites

- [Go](https://go.dev/doc/install) installed
- [GitHub CLI (`gh`)](https://cli.github.com/) authenticated

---

## Creating a New Release

### 1. Tag the commit

```bash
# Annotated tag (recommended)
git tag -a v2.1.2 -m "Release v2.1.2 - Short description"

# Push the tag
git push origin v2.1.2
```

### 2. Create the release

```bash
# Auto-generate changelog from commits since last tag
gh release create v2.1.2 \
  --title "v2.1.2 - Release Title" \
  --generate-notes

# Or with a custom body
gh release create v2.1.2 \
  --title "v2.1.2 - Release Title" \
  --notes "## What's New
- Feature A
- Bug fix B"
```

### 3. Attach assets (optional)

```bash
# Build the binary
make build

# Upload to the release
gh release upload v2.1.2 ./bin/wardex

# Upload the banner
gh release upload v2.1.2 doc/banner.png
```

---

## Updating an Existing Release

```bash
# Edit title and/or description
gh release edit v2.1.1 \
  --title "v2.1.1 - New Title" \
  --notes "Updated release notes"

# Upload additional assets
gh release upload v2.1.1 doc/banner.png
```

---

## Deleting a Release

```bash
# Delete the release (keeps the tag)
gh release delete v2.1.0

# Delete the tag as well
git tag -d v2.1.0
git push origin --delete v2.1.0
```

---

## Checklist Before Releasing

- [ ] All CI checks pass on `main`
- [ ] Version in `cli.go` or `banner.go` matches the tag
- [ ] README badges reflect the correct version
- [ ] Helm chart `Chart.yaml` `appVersion` matches the tag
- [ ] `make build` compiles without errors
- [ ] Changelog / release notes are written

---

## Versioning Convention

Wardex follows [Semantic Versioning](https://semver.org/):

| Bump | When |
|------|------|
| **Major** (`v2.0.0`) | Breaking API or CLI changes |
| **Minor** (`v2.1.0`) | New features, backward-compatible |
| **Patch** (`v2.1.2`) | Bug fixes only |
