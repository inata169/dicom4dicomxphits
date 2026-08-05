# Development handoff

Last updated: 2026-08-05

## Current state

- `main` contains 452 audited DICOM files and is synchronized with GitHub.
- PR #2 fixed `.trusted` symlink redirection in the audit workflow.
- Pull-request audit, post-merge audit, and Codex review passed.
- No known development issue remains open.

## Next session

1. Run `git pull --ff-only`.
2. Run `py -3.12 scripts/audit_dicom.py --check-checksums`.
3. Read `CONTRIBUTING.md` before changing DICOM data.

For data changes, update `MANIFEST.sha256` and merge only after the DICOM audit and review pass.
