# Pi cancellation patch

Base Pi revision: `b215884021491772a1eb7a9f92c6653a2a52a69d`.

The parent repository tracks this patch because Pi's local instructions require
explicit operator authorization for a Pi commit. The working checkout and built
runtime already contain it. Fresh checkouts can run:

```sh
bash patches/pi/apply.sh
cd pi/pi/packages/coding-agent
npm run build
cd ../../../../extensions
npm run build
npm run test:reliability
```

The helper applies both the generic cancellation fix and its nine-case faux
provider suite. It accepts an already-applied patch and rejects incompatible or
partially-applied trees. It does not build, commit, fetch or change provider
configuration. Rebuild the SDK and CLI before running Pluto.

Validation from the Pi root:

```sh
npm run check
cd packages/coding-agent
node ../../node_modules/vitest/dist/cli.js --run test/suite/agent-session-abort-continuation.test.ts
```

No real model API or target is used by the focused suite or Pluto's SDK integration
fixture. These checks establish cancellation behavior, not sandbox confinement.
