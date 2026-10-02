# Local Pi patches

Base Pi revision: `b215884021491772a1eb7a9f92c6653a2a52a69d`.

The operator authorized committing the Pi changes on 2026-10-01. The parent
repository's submodule reference now includes the cancellation fix and its test
suite. This patch remains available for checkouts at the base revision above.
Those older checkouts can run:

```sh
bash patches/pi/apply.sh
cd pi/pi/packages/coding-agent
npm run build
cd ../../../../extensions
npm run build
npm run test:reliability
```

The helper applies the generic cancellation fix and its nine-case faux provider
suite, plus the read-only settings fix and its focused tests. The settings fix
lets immutable project profiles load when sibling lock creation fails with
EROFS/EACCES; callbacks requesting writes still fail with the original lock
error. Ordinary writable locking and contention behavior remain unchanged.

Each patch can already be applied independently. The helper checks every pending
delta before changing files and rejects incompatible or partially applied
patches. It does not build, commit, fetch or change provider configuration.
Rebuild the SDK and CLI before running Pluto.

Validation from the Pi root:

```sh
GOMAXPROCS=1 GOMEMLIMIT=768MiB npm run check
cd packages/coding-agent
node ../../node_modules/vitest/dist/cli.js --run --maxWorkers=1 --no-file-parallelism test/suite/agent-session-abort-continuation.test.ts
node ../../node_modules/vitest/dist/cli.js --run --maxWorkers=1 --no-file-parallelism test/settings-readonly.test.ts test/settings-manager.test.ts test/settings-manager-bug.test.ts test/settings-diagnostics.test.ts
```

No real model API or target is used by the focused suite or Pluto's SDK integration
fixture. These checks establish cancellation behavior, not sandbox confinement.
Run checks sequentially on the 4 GB host. The Go memory target is soft; the
full-monorepo typecheck was observed using about 1.5 GB even with this target.
