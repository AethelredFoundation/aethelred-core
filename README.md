# Aethelred Core (Authority Notice)

Status: Transitional mirror (release-frozen, non-canonical for chain releases; authority explicitly restricted).

This repository currently overlaps with `aethelred-cosmos-node` and uses the same Go module path (`github.com/aethelred/aethelred`).

Enforced interim controls now in place:
- Do not assume both repos are independently authoritative.
- Verify release tags, security fixes, and patch provenance against the published authority policy and registry.
- Treat this repository as a mirror/transitional source unless explicitly designated canonical.
- `repo-authority.json` and repo-local authority CI guard mark this repo as non-release-authoritative and block releases.
- Direct feature development intended for canonical chain releases is disallowed while this repo is in release-frozen mirror mode.
- Mirror drift is checked via `.github/workflows/mirror-drift-check.yml`.

See:
- `docs/governance/core-disposition-ratification.md`
- `docs/security/threat-model.md`
- `SECURITY.md`
- `repo-authority.json`
