# Frontend design

Companion to [`docs/design.md`](design.md), focused on the Next.js + React UI in `frontend/`. Covers: component map, state model, SSE wire protocol, theming, build, and the trade-offs that landed differently from the rest of the codebase.

## What it is

A Next.js 15 (App Router) application on React 19 + TypeScript strict + Tailwind, with six routes: `/` (landing), `/triage` (form + report), `/dashboard` (statistics / observability / transparency), `/scorecard` (the sonnet-baseline scorecard rendered statically from committed result JSONs), `/guide` (framework explainer), and `/r` (a self-contained shared-report viewer, not in the nav). The header nav carries five tabs: Home, Triage, Dashboard, Scorecard, Guide. It is the primary interface for the triage agent: the user types a query (free text, a CVE ID, a product description, or Nmap XML), the UI streams the agent's progress as it happens, and renders the final `TriageReport` as a structured card - the deterministic SSVC verdict (SSVC is CISA's remediation-urgency methodology: one of Act / Attend / Track* / Track, computed server-side, never by the LLM), per-feed signal coverage (whether each external feed returned data, had no entry, or errored), severity/confidence, and per-CVE detail.

It is not a thin wrapper around the FastAPI surface; it adds:
- A Next.js-side `/api/triage` proxy that lets the browser talk same-origin (no CORS opened on the backend).
- Provider-hoisted run state so a triage started on one route keeps streaming across navigation, plus a `localStorage`-backed history sidebar (last 30 runs).
- A dark-only "Slate Recon" design system (no theme toggle) on a single CSS-variable token source.
- Report exports (Markdown, JSON, print-to-PDF) and a zero-infra shareable permalink (the whole report gzip-encoded into the URL fragment).
- Strip + display of the `<UNTRUSTED_CONTENT>...</UNTRUSTED_CONTENT>` markers as a styled quote block, so the operator sees the security fence semantically without raw XML-tag clutter.

## File map

```
frontend/src/
├── app/
│   ├── layout.tsx               # root layout; loads Inter + JetBrains Mono via next/font
│   ├── page.tsx                 # landing: split hero (copy + pipeline diagram), pillars, tools
│   ├── triage/page.tsx          # form + progress stream + report + history sidebar
│   ├── dashboard/page.tsx       # ARIA tablist: statistics / observability / transparency
│   ├── scorecard/page.tsx       # static scorecard: sonnet baseline from committed JSONs
│   ├── guide/page.tsx           # framework explainer with sticky TOC
│   ├── r/page.tsx               # shared-report viewer: decodes a report from the URL fragment
│   ├── globals.css              # Tailwind directives + the Slate Recon CSS-variable tokens
│   └── api/
│       ├── triage/route.ts      # SSE proxy to http://agent-api:8000/v1/triage
│       └── meta/route.ts        # proxy to /v1/meta (transparency view)
│
├── components/
│   ├── providers.tsx            # client wrapper mounting TriageProvider + CommandPaletteProvider
│   ├── header.tsx               # sticky macro-tab nav + palette trigger + GitHub link
│   ├── command-palette.tsx      # Cmd+K provider: keydown listener, command rendering, triage ctx
│   ├── demo-banner.tsx          # demo-mode banner naming the capture model
│   ├── triage-form.tsx          # textarea + example chips + Triage/Stop buttons
│   ├── progress-stream.tsx      # ordered list of node events with in-flight spinner
│   ├── triage-report-view.tsx   # TriageReport card: SSVC ladder, coverage strip, CVEs, exports
│   ├── history-sidebar.tsx      # localStorage-backed run list (lg+ viewports)
│   ├── icons/github-logo.tsx    # inline SVG (lucide v1 dropped brand icons)
│   ├── dashboard/               # kpi-card, charts (Recharts), statistics / observability / transparency tabs
│   └── ui/                      # shadcn-style primitives (copied, not imported):
│                                #   button, badge, card, textarea, separator, scroll-area,
│                                #   collapsible, skeleton, command (cmdk + radix-dialog shell)
│
├── demo/
│   ├── config.ts                # DEMO_MODE flag + the capture model (sonnet)
│   ├── fixtures.ts + fixtures/  # 7 committed real SSE captures (full SSVC ladder)
│   ├── replay.ts                # replays a capture as a paced SSE stream
│   └── scorecard/               # slimmed eval / retrieval / redteam JSONs + provenance
│
├── hooks/
│   ├── use-triage.tsx           # Provider-backed run state machine, SSE driver, abort, history patch
│   └── use-history.ts           # localStorage CRUD with quota safety (newest-first, cap 30)
│
└── lib/
    ├── types.ts                 # mirrors src/sec_recon_agent/agent/schema.py
    ├── sse.ts                   # fetch+ReadableStream SSE parser
    ├── stats.ts                 # history aggregation + real node-waterfall builder
    ├── scorecard.ts             # aggregations for /scorecard, mirrors eval/metrics.py
    ├── markdown-export.ts       # TriageReport -> Markdown / JSON download helpers
    ├── permalink.ts             # gzip+base64url a report into a shareable URL fragment
    ├── commands.ts              # static 56-command registry for the palette
    ├── guide-data.ts            # guide SECTIONS (sections + external refs), shared with the palette
    ├── agent-meta.ts            # /v1/meta loader (demo snapshot or proxy fetch)
    ├── nav-events.ts            # cross-component window events (dashboard tab sync)
    └── utils.ts                 # cn() class-name merger
```

There is no `theme-toggle.tsx`: the app is dark-only (see [Theming](#theming)).

## State model

Two custom hooks own the page state.

**`useTriage()`** is a React Context (`TriageProvider`) mounted at the layout via `providers.tsx`, so run state and the in-flight `AbortController` live **above** the routes: a triage started on `/` keeps streaming when the user navigates to `/dashboard`. Run state:

```ts
{
  isRunning: boolean
  nodes: string[]           // node class names accumulated as they stream in
  report: TriageReport | null
  error: string | null
  startedAt: number | null
  durationMs: number | null
  currentEntryId: string | null
}
```

API: `run(query)`, `cancel()`, `reset()`, plus the history surface (`entries`, `selectEntry`, `clearHistory`, `draftQuery`). The hook holds an `AbortController` ref so the `Stop` button reliably tears down the in-flight HTTP request. Selecting a history entry prefills the form with that entry's query only when the draft is empty or still an untouched programmatic fill; a draft the user is authoring is never clobbered.

**`useHistory()`** persists past runs in `localStorage` (key `sec-recon-history`, newest-first, cap 30). Failures on read/write are swallowed (corrupted storage starts fresh; quota-exceeded does not crash the UI).

On submit, `run()` creates a `HistoryEntry`, `add()`s it to the sidebar, then drives the SSE stream - capturing outer-scope values **before** dispatching `setState` (React 18 defers the updater to the render phase; capturing inside it would race the surrounding `await` chain). As the stream advances it records each `node` event's arrival time and, at `final`, snapshots them onto the entry (`nodeEvents`) together with the token `usage`, so the observability view draws a *measured* waterfall rather than a synthesized one.

## SSE wire protocol (browser to Next.js to FastAPI)

The browser never talks to FastAPI directly. Three hops:

```
Browser            Next.js (/api/triage)          FastAPI (/v1/triage)
   │                       │                              │
   │  POST {"query":...}   │                              │
   │---------------------> │                              │
   │                       │  POST {"query":...}          │
   │                       │ ---------------------------> │
   │                       │                              │
   │                       │  text/event-stream chunks    │
   │                       │ <--------------------------- │
   │  text/event-stream    │                              │
   │ <-------------------- │                              │
```

The Next.js route (`src/app/api/triage/route.ts`) is a passthrough: it reads the upstream `ReadableStream` and returns it as the response body. SSE headers (`Content-Type: text/event-stream`, `Cache-Control: no-cache, no-transform`, `X-Accel-Buffering: no`) are set explicitly so reverse proxies (CDN, nginx) do not buffer the stream.

The browser-side parser (`lib/sse.ts`) uses `fetch()` + `ReadableStream` rather than the built-in `EventSource` API because `EventSource` does not support POST with a body. It buffers until `\n\n` (the SSE frame separator), then splits each frame on newlines and extracts the `event:` and `data:` lines. SSE comment lines (`: ` prefix, used as keepalives) are skipped.

Event payloads emitted by the backend:

```
event: started        data: {"query": "..."}
event: node           data: {"node": "UserPromptNode" | "ModelRequestNode" | "CallToolsNode" | "End"}
event: final          data: TriageReport (full JSON, incl. the server-stamped SSVC verdict + signal coverage)
event: usage          data: {"input_tokens": N, "output_tokens": N, "requests": N}   # after final
event: error          data: {"type": "...", "message": "..."}
```

`node` events are the streaming progress signal. The UI renders one row per event with the friendly label and a spinner on the in-flight (latest) one. When `final` arrives, the report renders below the progress list with a fade-in animation. When `error` arrives, an error card replaces the report.

## Untrusted-content fence rendering

`CVEDetail.description` and similar free-text fields come back from the backend wrapped with `<UNTRUSTED_CONTENT>...</UNTRUSTED_CONTENT>` markers (see `src/sec_recon_agent/mcp_server/security.py` and the threat model in [`design.md`](design.md)).

The frontend strips the markers for display and renders the body inside a `border-l-2 muted` quote block with a small label "NVD description (untrusted vendor text)" above it. The label is the visible signal that the text is vendor-authored; the styling visually de-emphasizes it relative to the agent's own summary. The raw markers are never shown to the operator.

If a field is not fenced (some upstream sources do not have free text), it renders inline like normal copy.

## Report export and share

Every report card carries three exports plus a share link, all client-side with zero new dependencies:

- **Export .md** builds a Markdown document (severity / confidence header, summary, recommended action, per-CVE details with KEV / ransomware / EPSS, ATT&CK techniques with mitigations, the full reasoning chain) and triggers a browser download (`lib/markdown-export.ts`). No backend route.
- **Raw JSON** downloads the `TriageReport` as returned, verdict and coverage included.
- **Export PDF** calls `window.print()` with an `@media print` stylesheet in `globals.css` that scopes visibility to the report block, hides the chrome, and forces an A4 light-on-white layout; the user picks "Save as PDF" in the system dialog. Native multi-page.
- **Copy link** gzip-encodes the whole report into the URL fragment (`lib/permalink.ts`); `/r` decodes it locally. The fragment never reaches a server; past a size cap it falls back to suggesting the JSON export. The minted URL is basePath-aware (`NEXT_PUBLIC_BASE_PATH`), so links copied on the Pages demo point inside the project sub-path.

## Command palette

`Cmd+K` (macOS) / `Ctrl+K` (elsewhere), or the Search button in the header, opens a command palette with 56 commands in 7 groups: report actions (copy link, export .md / JSON / PDF - visible only while a report is on screen, PDF only where `#printable-report` is in the DOM), page navigation, dashboard tab jumps, the 7 demo triage runs (live mode submits the same query to the real backend), the 12 guide sections, the guide's 23 external references, and project actions (GitHub, copy system prompt).

The registry is a static module (`lib/commands.ts`); context-dependent commands gate through a `visible(ctx)` predicate rather than conditional construction, so the filter always sees a stable item set. Section and reference commands consume the same `lib/guide-data.ts` the guide page renders from - one source, no drift. The binding is platform-split on purpose: registering `Ctrl+K` on macOS too would hijack readline kill-line inside the triage textarea.

Fuzzy matching and combobox accessibility come from `cmdk`; the dialog shell is composed from `@radix-ui/react-dialog` directly (see the decisions log for why not cmdk's built-in dialog).

## Theming

**"Slate Recon" - dark-only.** A security triage console reads dark-first, so the app ships one tuned palette instead of a light/dark toggle. It is a cool blue-slate NOC surface with a single cyan signal (`#22D3EE`, main CTA / interactive) and an indigo focus accent (`#818CF8`), in the idiom of Grafana / Datadog / Vercel. It replaced the earlier Catppuccin Latte/Macchiato dual theme.

All color lives in **one source**: CSS variables in `src/app/globals.css` (HSL channels, so Tailwind's `hsl(var(--token))` and the `/alpha` modifier keep working). There is no `.dark` toggle and no light token set; `color-scheme: dark` is set on `:root`. The categorical chart palette and the diverging severity ramp are also tokens (`--chart-*`, `--severity-*`).

The severity ramp (`red -> orange -> gold -> blue -> grey`) is deliberately **not** red-vs-green, and every severity/coverage indicator in the UI pairs hue with a shape/icon + text label, so nothing depends on color alone (colorblind- and print-safe). Domain severity classes (`.severity-critical`, ...) resolve from the ramp tokens.

One deliberate duplication: `components/dashboard/charts.tsx` holds the severity + categorical colors as literal hex because Recharts writes them onto SVG `fill` attributes, where CSS custom properties do not resolve. Those literals mirror the `--severity-*` / `--chart-*` tokens; `globals.css` is the canonical source and the two are kept in sync by hand (noted in the file).

Fonts are loaded via `next/font` (Inter for sans, JetBrains Mono for mono) and exposed as `--font-sans` / `--font-mono`; the Tailwind `fontFamily` tokens point at those variables. Telemetry (CVE IDs, ports, scores, token counts) renders in JetBrains Mono with `tabular-nums`.

## Build

```
Dockerfile (frontend/)
├── deps stage     : node:22-alpine + npm install --legacy-peer-deps
├── builder stage  : npm run build  (produces .next/standalone)
└── runtime stage  : node:22-alpine + curl + tini + non-root `node` user
                    Copies only .next/standalone and .next/static
                    Healthcheck: curl GET /
                    PID 1: tini, CMD: node server.js
```

`output: "standalone"` in `next.config.mjs` is the load-bearing piece: it produces a self-contained runtime bundle so the final image does not need `node_modules` or the entire source tree, only ~150 MB of compiled assets.

`--legacy-peer-deps` papers over Next 15's peer-range on the React 19 RC tag; Next 15.x supports React 19 GA at runtime but the package.json range is pinned to an RC string. Future Next minors should make this flag unnecessary.

### Demo build (GitHub Pages)

`NEXT_PUBLIC_DEMO_MODE=1` flips the build to `output: "export"`: a fully static, keyless bundle that replays the committed real SSE captures in `src/demo/` instead of calling the backend - no Anthropic key, no seed, no server. `scripts/build-demo.mjs` stashes the `/api` route handlers for the duration of the build (route handlers are incompatible with static export) and restores them even if the build fails. `NEXT_PUBLIC_BASE_PATH` serves the export under `/sec-recon-agent` for the GitHub Pages project site; it stays empty on root-served hosts. The demo build also sets `trailingSlash` (directory-style export): without it, the client router asks for the root route's RSC payload at `${basePath}.txt`, which sits outside the project sub-path on Pages and 404s on every Home prefetch. `.github/workflows/deploy-demo.yml` rebuilds and redeploys on every `frontend/**` push to main.

The demo banner names the capture model (sonnet) so the replayed runs are honestly attributed. Replay pacing is compressed for the visitor, but history entries keep the real measured timings, so the observability waterfall stays honest.

## Local development

```bash
cd frontend
npm install --legacy-peer-deps
npm run dev          # http://localhost:3000, HMR enabled
```

For dev mode against the host-side backend (not Docker), set `AGENT_API_URL=http://localhost:8000` in the shell that runs `npm run dev`. The default `http://agent-api:8000` is the compose-internal hostname.

```bash
npm run type-check   # tsc --noEmit
npm run lint         # next lint
npm run build        # production build
```

## What is deliberately not in the frontend

- **No client-side LLM calls.** The `ANTHROPIC_API_KEY` lives only in the backend process; the frontend never sees it.
- **No telemetry beacons.** No analytics scripts, no error-reporting SaaS. The page is self-contained.
- **No service worker / PWA.** Out of scope for a single-tenant demo.
- **No auth UI.** Backend is unauthenticated by design; adding a login screen here without backend auth would be theatre.
- **No streaming React UI library (Vercel AI SDK, etc.).** Evaluated and dropped; the SSE wrapper is 50 lines and the agent's protocol does not fit the SDK's chat-completion shape.
- **One deliberate dependency exception: `cmdk` + `@radix-ui/react-dialog` (both exact-pinned) for the command palette.** The bias stays "hand-roll small surfaces", but fuzzy ranking plus combobox accessibility plus focus management over 56 mixed nav/action items is where hand-rolling costs more than the dependency. radix-dialog was already in the tree transitively via cmdk; making it direct lets the dialog shell carry a proper hidden `DialogTitle`.

## Decisions log

| Decision | Why | Alternative rejected |
|---|---|---|
| Next.js 15 App Router | Same React/TS stack the target roles cite, plus a built-in API route for the SSE proxy | Vite SPA (no native API route) |
| shadcn-style primitives (Radix + CVA, copied) | Small bundle, design tokens flow into Tailwind via CSS variables | Component libraries (MUI / Mantine) - too heavy, design lock-in |
| Dark-only "Slate Recon" on one token source | A security console is dark-first; one tuned palette beats a maintained light/dark pair, and single-source kills the earlier three-way color drift | Catppuccin dual theme + toggle - dev-dotfiles read, colors fragmented across CSS / charts / diagram |
| Real node waterfall from client-timestamped `node` events | Honest measured timing on a transparency-thesis project; zero backend change | Even-split synthesis by `reasoning_chain` length - fabricated, retired |
| Permalink via URL fragment (`#r=`, gzip+base64url) | Shareable report with no backend, no storage; the fragment never reaches the server | Server-side share links - would require a DB, an ID scheme, and a leak surface |
| Plain Tailwind animations, `prefers-reduced-motion` guard | Type-safe, zero runtime cost, respects the OS motion preference | framer-motion 11.x - TS strict mode conflicts with motion.* + onClick |
| `localStorage` history | Demo scope, no backend persistence needed | Server-side history - would require a DB and auth |
| `fetch()` + ReadableStream for SSE | EventSource does not support POST body; the parser is 50 lines | Vercel AI SDK - wrong protocol shape |
| `output: "standalone"` Docker | ~150 MB image, no separate nginx | Static export - loses the `/api/triage` route (used only for the keyless demo build, where the routes are stashed) |
| `cmdk` command palette, exact-pinned | Fuzzy ranking + combobox a11y over 56 items beats hand-rolling; unstyled, so Slate Recon tokens apply untouched | Hand-rolled listbox + filter (a11y/focus surface too large for the payoff); kbar (heavier, animation dep); cmdk's built-in `Command.Dialog` (no `DialogTitle`, trips Radix's a11y console error - dialog shell composed from radix-dialog directly instead) |
