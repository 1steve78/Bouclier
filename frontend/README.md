# Bouclier Frontend

The independent Next.js application provides the Bouclier public landing page and investigation workspace. It uses clearly labeled sample data and does not run live scans, query threat feeds, or verify blockchain reports.

## Requirements

- Node.js 20.9 or later
- npm

## Development

From this directory:

```powershell
npm install
npm run dev
```

Open `http://localhost:3000`. To validate changes, run:

```powershell
npm run lint
npm run typecheck
npm run build
```

Copy `.env.example` to `.env.local` to prepare for future HTTP API integration. `NEXT_PUBLIC_API_BASE_URL` is intentionally not used by the mock-backed services yet. Do not put API secrets in `NEXT_PUBLIC_*` variables; values with that prefix are included in browser bundles.

## Integration boundary

Typed contracts and service functions live under `src/lib/`. Replace the mock implementations with calls matching the repository's documented OpenAPI contract when the Go HTTP service is available. Until then, keep outputs visibly labeled as demonstrations and avoid presenting missing lookups as passed checks.
