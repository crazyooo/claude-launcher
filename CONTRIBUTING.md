# Contributing

Thanks for considering a contribution. This repository is a **Public Beta** of a
macOS Claude environment detector with optional PF-based direct-connection
protection.

## Good first contributions

- Detector copy, UX clarity, and offline unit tests
- Documentation fixes (README, quickstart, security notes)
- Hardening of installers and privilege checks with regression tests
- Bug reports with macOS version, Xcode version, and whether protect helpers
  are installed

## Please do not open PRs that

- Add whole-machine routing / TUN takeover as a default product path
- Widen passwordless sudoers beyond exact `status`
- Disable TLS verification, invent `protection_verified`, or fake detector pass
- Bundle unsigned third-party proxy binaries without a clear license plan
- Run or require RoutingCore Live tests that mutate the contributor's network
  as part of CI defaults

## Development

```sh
DEVELOPER_DIR=/Applications/Xcode-16.4.app/Contents/Developer \
  swift test --disable-sandbox --filter LauncherCoreTests

PYTHONPATH=tools:tools/l4 /usr/bin/python3 -B -m unittest \
  claude_protect_pf_tests claude_protect_guard_tests \
  router_pf_root_hook_tests detector_installer_tests \
  install_guard_daemon_tests install_sudoers_nopasswd_tests
```

Default product identifiers use the `local.crazyooo.*` namespace (GitHub user
`crazyooo`). Keep that stable unless a migration plan for installed helpers is
included. Pre-public `local.crazymax.*` leftovers should be retired, not mixed.

Legacy `RoutingCore` code remains for compatibility and is not the accepted
product path. Prefer changes under detector / protect surfaces.

## Pull requests

1. Keep diffs focused.
2. Add or update tests for behavior changes.
3. Do not commit diagnostics, personal IPs, journals, or build products.
4. Mention any privilege, PF, or installer impact in the PR description.
