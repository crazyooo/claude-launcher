# Security Policy

## Supported versions

Security fixes target the current `main` branch (v0.16.x Public Beta and newer).
Older local installs that still use legacy passwordless wrappers should migrate
with the installer documented in `docs/for-others-quickstart.md` before relying
on this project for privileged operations.

## Privileged components

Optional direct-connection protection installs code under:

`/Library/PrivilegedHelperTools/local.crazyooo.claude-protect/`

Only the exact `status` command is intended to be passwordless. Enable / disable
and other mutations require macOS administrator authorization and must execute
the system-owned entry, never a user-writable repository or App Resources script.

Do not widen sudoers to run arbitrary Python from a clone. Do not restore old
`/usr/local/sbin/claude-protect-*` wrappers.

## Reporting a vulnerability

Please open a [GitHub Security Advisory](https://github.com/crazyooo/claude-launcher/security/advisories/new)
for this repository. Include:

- affected commit or version
- whether a privileged helper / PF / sudoers path is involved
- reproduction steps that do not require publishing a weaponized exploit

If advisory filing is unavailable, open a private contact via the repository
owner on GitHub. Do not file a public issue for unpatched privilege-escalation
or root-execution bugs.

## Out of scope

- Misconfiguration of a third-party proxy client
- Network paths blocked by an upstream provider
- Running unfiltered RoutingCore Live tests on a personal machine
