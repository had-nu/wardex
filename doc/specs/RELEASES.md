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
git tag -a v1.2.0 -m "Release v1.2.0 - Short description"

# Push the tag
git push origin v1.2.0
```

### 2. Create the release

```bash
# Auto-generate changelog from commits since last tag
gh release create v1.2.0 \
  --title "v1.2.0 - Release Title" \
  --generate-notes

# Or with a custom body
gh release create v1.2.0 \
  --title "v1.2.0 - Release Title" \
  --notes "## What's New
- Feature A
- Bug fix B"
```

### 3. Attach assets (optional)

```bash
# Build the binary
go build -o wardex .

# Upload to the release
gh release upload v1.2.0 ./wardex

# Upload the banner
gh release upload v1.2.0 doc/banner.png
```

---

## Updating an Existing Release

```bash
# Edit title and/or description
gh release edit v1.1.0 \
  --title "v1.1.0 - New Title" \
  --notes "Updated release notes"

# Upload additional assets
gh release upload v1.1.0 doc/banner.png
```

---

## Deleting a Release

```bash
# Delete the release (keeps the tag)
gh release delete v1.1.0

# Delete the tag as well
git tag -d v1.1.0
git push origin --delete v1.1.0
```

---

## Checklist Before Releasing

- [ ] All CI checks pass on `main`
- [ ] Version in `banner.go` matches the tag
- [ ] README badges reflect the correct version
- [ ] `go build` compiles without errors
- [ ] Changelog / release notes are written

---

## Versioning Convention

Wardex follows [Semantic Versioning](https://semver.org/):

| Bump | When |
|------|------|
| **Major** (`v2.0.0`) | Breaking API or CLI changes |
| **Minor** (`v1.2.0`) | New features, backward-compatible |
| **Patch** (`v1.1.1`) | Bug fixes only |
