# Contributing

## Prerequisites

- macOS 13 or newer with Xcode or Command Line Tools (`swift` 5.10+)
- Node.js `22.12` or newer (the Worker test suite uses built-in `node:sqlite`, `node:crypto`, and `node:test`, so there is no `npm install` step)

## Running checks locally

Run all four checks before opening a pull request:

```sh
# 1. Build all Swift targets (SeatStamp + license-tool) and run the selftest suite
swift build && swift run selftest

# 2. Cloudflare Worker and SQLite Durable Object tests
node --test worker/worker.test.mjs

# 3. The walkthrough site's examples still match the real formats
node --test site/site.test.mjs

# 4. Standalone menu-bar example app build
cd example && swift build
```

For interactive Worker testing with `wrangler dev`, copy [`worker/.dev.vars.example`](worker/.dev.vars.example) to `worker/.dev.vars` (`worker/.dev.vars` is gitignored) and run:

```sh
npx wrangler -c worker/wrangler.jsonc dev
```

## Pull request guidelines

- Open an issue first before working on wire-protocol, ticket-format, or Durable Object schema changes. The frozen constants are listed in [`docs/architecture.md`](docs/architecture.md#wire-format-constants).
- Keep zero third-party runtime dependencies in both the Swift package (`Package.swift`) and the Cloudflare Worker (`worker/worker.js`).
- Preserve Cloudflare Workers Free plan compatibility (`new_sqlite_classes` SQLite Durable Objects) and the storage rules in docs/privacy.md (no email addresses or IP addresses written to SQLite or logs; the raw purchase key only in the 24-hour handoff record).
- Keep issued `LK1-` tickets and signed `version.json` manifests valid: their byte formats are frozen (see [`docs/architecture.md`](docs/architecture.md#wire-format-constants)).
- If you touch signing, hashing, or canonicalization logic, verify cross-language parity against [`fixtures/golden-vectors.json`](fixtures/golden-vectors.json).
- `swift run selftest` fails if any `.key`, `.pem`, or `.pkcs8` file is present in the tree (hidden files included; `.git`, `.build`, `.swiftpm`, `.wrangler`, and `node_modules` are skipped), if any source, markdown, JSON, or YAML file contains em-dashes or en-dashes, or if the `license-tool` binary was not built.
