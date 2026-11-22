# Contributing to this fork

## Workflow
1. File an issue first (search open AND closed ones to avoid duplicates).
2. Branch off the mainline:
   git switch -c fix/<issue-number>-short-name vlm_master
3. Push, open a PR targeting `vlm_master` with "Fixes #<issue>".
4. Keep PRs small; wait for CI.

## Branching model
- `vlm_master` is the protected mainline (ruleset `asn1c-ruleset`):
  no direct pushes, everything via PR.
- Topic branches: `fix/…`, `feat/…`, `docs/…`, `chore/…`.
- Fork of `mouse07410/asn1c` — keep `vlm_master` in sync:
  ```
  git remote add upstream https://github.com/mouse07410/asn1c.git   # once
  git fetch upstream
  git switch -c sync/upstream-vlm_master vlm_master
  git merge upstream/vlm_master
  git push -u origin sync/upstream-vlm_master    # then open a PR
  ```

## Commits
Short imperative subject (`fix: …`, `feat: …`); body explains why, not what.

## Issues vs upstream
Stock asn1c bugs → file on `mouse07410/asn1c`.
Fork-specific changes → file here, label `fork-specific`.