# Off-site observer

This directory is an independent Git repository, registered as a submodule in
the parent Homelab checkout. Read `README.md`, `SECURITY.md` and `docs/REVIEW.md`
before changes. Parent repository instructions also apply when working there.

- GitLab `origin` is primary. Push there; GitLab mirrors to GitHub. Preserve the
  independent history and avoid routine direct pushes to the GitHub mirror.
- Commit service files here; update the parent submodule pointer separately.
  Preserve other sessions' working trees and index entries.
- This source is public. Never add real host/network inventory, tokens, recipient
  details, private configuration, state, response bodies or production logs.
- Keep default execution inert and activation explicit. Source work does not
  authorize host provisioning, deployment, network changes or recipient contact.
- Validate Python changes with `make check` and `make demo`. Check local links and
  `git diff --check` for documentation-only changes. Keep deployment gates explicit.
