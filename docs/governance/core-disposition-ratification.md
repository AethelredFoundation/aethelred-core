# `aethelred-core` Disposition (Transitional Mirror / Release-Frozen)

Status: Proposed for Foundation ratification

Date: 2026-02-24

## Decision (Proposed)

`AethelredFoundation/aethelred-core` is designated a **release-frozen transitional mirror** for the Go chain implementation track.

It is **not** release-authoritative while it shares the same Go module path (`github.com/aethelred/aethelred`) with `AethelredFoundation/aethelred-cosmos-node`.

## Operational Rules

- No production releases or prereleases from this repository.
- No direct feature development intended for canonical chain releases.
- Security fixes and feature work land in `aethelred-cosmos-node` first.
- This repo may retain documentation, compatibility, or mirror snapshots during transition.

## Enforcement

- `repo-authority.json` marks `release_authority=false`
- `.github/workflows/repo-authority-guard.yml` blocks releases
- `.github/workflows/mirror-drift-check.yml` reports divergence from canonical repo

## Exit Paths

1. Archive repository (preferred if no longer needed)
2. Maintain mirror-only mode with automated sync
3. Repurpose with a distinct module path and updated authority manifest

## Ratification Sign-Offs

- Foundation governance delegate: `PENDING`
- Protocol engineering lead: `PENDING`
- Security lead / auditor liaison: `PENDING`
- Ratified on: `PENDING`
