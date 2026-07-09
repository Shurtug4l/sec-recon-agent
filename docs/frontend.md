# Frontend design

Companion to [`docs/design.md`](design.md), focused on the Next.js + React UI in `frontend/`. Covers: component map, state model, SSE wire protocol, theming, build, and the trade-offs that landed differently from the rest of the codebase.

## What it is

A Next.js 15 (App Router) application on React 19 + TypeScript strict + Tailwind, with seven routes: `/` (landing), `/triage` (form + report), `/dashboard` (statistics / observability / transparency), `/scorecard` (the sonnet-baseline scorecard rendered statically from committed result JSONs), `/case-study` (the design narrative as a guided tour, twin of `docs/case_study.md`), `/guide` (framework explainer), and `/r` (a self-contained shared-report viewer, not in the nav). The header nav carries six tabs: Home, Triage, Dashboard, Scorecard, Case study, Guide. It is the primary interface for the triage agent: the user types a query (free text, a CVE ID, a product description, or Nmap XML), the UI streams the agent's progress as it happens, and renders the final `TriageReport` as a structured card - the deterministic SSVC verdict (SSVC is CISA's remediation-urgency methodology: one of Act / Attend / Track* / Track, computed server-side, never by the LLM), per-feed signal coverage (whether each external feed returned data, had no entry, or errored), severity/confidence, and per-CVE detail.

It is not a thin wrapper around the FastAPI surface; it adds:
- A Next.js-side `/api/triage` proxy that lets the browser talk same-origin (no CORS opened on the backend).
- Provider-hoisted run state so a triage started on one route keeps streaming across navigation, plus a `localStorage`-backed history sidebar (last 30 runs).
- A dual-theme "Editorial instrument" design system (dark instrument / light technical paper) on a single CSS-variable token source, with a hydration-safe theme toggle.
- Report exports (Markdown, JSON, print-to-PDF) and a zero-infra shareable permalink (the whole report gzip-encoded into the URL fragment).
- Strip + display of the `<UNTRUSTED_CONTENT>...</UNTRUSTED_CONTENT>` markers as a styled quote block, so the operator sees the security fence semantically without raw XML-tag clutter.

## File map

```
frontend/src/
├── app/
│   ├── layout.tsx               # root layout; three fonts via next/font + pre-paint theme script
│   ├── page.tsx                 # landing: hero (copy + animated SSVC ladder), how-it-works, pillars, tools
│   ├── triage/page.tsx          # form + progress stream + report + history sidebar
│   ├── dashboard/page.tsx       # ARIA tablist: statistics / observability / transparency
│   ├── scorecard/page.tsx       # scorecard shell (title + provenance) around the tabbed bands
│   ├── case-study/page.tsx      # design-narrative tour: hash-driven rail, 12 panels, 6-layer strip
│   ├── guide/page.tsx           # master-detail explainer: hash-driven rail + one panel at a time
│   ├── r/page.tsx               # shared-report viewer: decodes a report from the URL fragment
│   ├── globals.css              # Tailwind directives + the dual-theme CSS-variable tokens
│   └── api/
│       ├── triage/route.ts      # SSE proxy to http://agent-api:8000/v1/triage
│       └── meta/route.ts        # proxy to /v1/meta (transparency view)
│
├── components/
│   ├── providers.tsx            # client wrapper mounting TriageProvider + CommandPaletteProvider
│   ├── header.tsx               # sticky macro-tab nav + palette trigger + theme toggle + GitHub link
│   ├── theme-toggle.tsx         # flips data-theme on <html>, persists to localStorage
│   ├── ssvc-ladder-hero.tsx     # landing signature: SSVC ladder cycling four real verdicts
│   ├── command-palette.tsx      # Cmd+K provider: keydown listener, command rendering, triage ctx
│   ├── demo-banner.tsx          # demo-mode banner naming the capture model
│   ├── triage-form.tsx          # textarea + example chips + Triage/Stop buttons
│   ├── progress-stream.tsx      # ordered list of node events with in-flight spinner
│   ├── triage-report-view.tsx   # TriageReport card: SSVC ladder, coverage strip, CVEs, exports
│   ├── history-sidebar.tsx      # localStorage-backed run list (lg+ viewports)
│   ├── icons/github-logo.tsx    # inline SVG (lucide v1 dropped brand icons)
│   ├── dashboard/               # kpi-card, charts (Recharts severity bars + plain-DOM tool bars),
│   │                            #   statistics / observability / transparency tabs
│   ├── scorecard/               # scorecard-bands: the KPI row as an ARIA tab rail + five band panels
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
│   ├── use-history.ts           # localStorage CRUD with quota safety (newest-first, cap 30)
│   └── use-theme.ts             # subscribes to <html data-theme> (useSyncExternalStore)
│
└── lib/
    ├── types.ts                 # mirrors src/sec_recon_agent/agent/schema.py
    ├── sse.ts                   # fetch+ReadableStream SSE parser
    ├── stats.ts                 # history aggregation + real node-waterfall builder
    ├── scorecard.ts             # aggregations for /scorecard, mirrors eval/metrics.py
    ├── markdown-export.ts       # TriageReport -> Markdown / JSON download helpers
    ├── permalink.ts             # gzip+base64url a report into a shareable URL fragment
    ├── commands.ts              # static 58-command registry for the palette
    ├── guide-data.ts            # guide SECTIONS (sections + external refs), shared with the palette
    ├── agent-meta.ts            # /v1/meta loader (demo snapshot or proxy fetch)
    ├── nav-events.ts            # cross-component window events (dashboard tab sync)
    └── utils.ts                 # cn() class-name merger
```

Theme state deliberately has no React context: `<html data-theme>` is the runtime source of truth and `use-theme.ts` subscribes to the attribute itself, so anything can flip it (see [Theming](#theming)).

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

## Grounding provenance render

Since the backend stamps `TriageReport.grounding` (deterministic post-run claim verification, PR #112), the report view surfaces it in two places:

- **Badge** in the header row, next to the model's self-assessed confidence: `grounded N/N`, `suspect K/N`, or `grounding not evaluated`, with icon + hue redundant encoding (`suspect` renders as warning, not destructive - destructive stays reserved for real-world danger signals like KEV). The deliberate pairing: confidence is what the model says about itself, grounding is what the server verified; the two tooltips cross-reference each other. Clicking the badge scrolls to and opens the detail panel.
- **Collapsible panel** (`#grounding-section`, between ATT&CK and the reasoning chain) carrying the same `deterministic · server-computed` authority chip as the SSVC verdict, the per-status claim counters, and the findings list. `findings` holds only non-supported claims (the wire payload is bounded by design; supported claims are counted, not listed), each with subject / report field / status / evidence note; CVE subjects anchor-link to their card. `not_evaluated` renders as an honest skip, `truncated` is labeled. The panel opens by default when the verifier flagged something.

Reports restored from pre-grounding localStorage history or permalinks have no `grounding` key: badge and panel simply do not render (same defensive pattern as `ssvc`).

## Report export and share

Every report card carries three exports plus a share link, all client-side with zero new dependencies:

- **Export .md** builds a Markdown document (severity / confidence header, summary, recommended action, per-CVE details with KEV / ransomware / EPSS, ATT&CK techniques with mitigations, the grounding verification, the full reasoning chain) and triggers a browser download (`lib/markdown-export.ts`). No backend route.
- **Raw JSON** downloads the `TriageReport` as returned, verdict and coverage included.
- **Export PDF** calls `window.print()` with an `@media print` stylesheet in `globals.css` that scopes visibility to the report block, hides the chrome, and forces an A4 light-on-white layout; the user picks "Save as PDF" in the system dialog. Native multi-page.
- **Copy link** gzip-encodes the whole report into the URL fragment (`lib/permalink.ts`); `/r` decodes it locally. The fragment never reaches a server; past a size cap it falls back to suggesting the JSON export. The minted URL is basePath-aware (`NEXT_PUBLIC_BASE_PATH`), so links copied on the Pages demo point inside the project sub-path.

## Command palette

`Cmd+K` (macOS) / `Ctrl+K` (elsewhere), or the Search button in the header, opens a command palette with 58 commands in 7 groups: report actions (copy link, export .md / JSON / PDF, show grounding verification - visible only while a report is on screen, PDF and grounding only where the report view is in the DOM), page navigation, dashboard tab jumps, the 7 demo triage runs (live mode submits the same query to the real backend), the 12 guide sections, the guide's 23 external references, and project actions (GitHub, copy system prompt).

The registry is a static module (`lib/commands.ts`); context-dependent commands gate through a `visible(ctx)` predicate rather than conditional construction, so the filter always sees a stable item set. Section and reference commands consume the same `lib/guide-data.ts` the guide page renders from - one source, no drift. The binding is platform-split on purpose: registering `Ctrl+K` on macOS too would hijack readline kill-line inside the triage textarea.

Fuzzy matching and combobox accessibility come from `cmdk`; the dialog shell is composed from `@radix-ui/react-dialog` directly (see the decisions log for why not cmdk's built-in dialog).

## Theming

**"Editorial instrument" - one design system, two themes.** The dark default is the *instrument*: the cool blue-slate NOC surface inherited from "Slate Recon", with a single cyan signal (`#22D3EE`, main CTA / interactive) and an indigo focus accent (`#818CF8`). The light theme is the *technical paper*: warm off-white (`#F7F5F0`), near-black ink, the cyan darkened to `#0E7490` so it holds contrast on paper. This reverses the earlier dark-only decision (see the decisions log).

`data-theme` on `<html>` switches the theme. An inline pre-paint script in `layout.tsx` stamps the stored preference before first paint (falling back to `prefers-color-scheme`, then dark), so there is no theme flash; the header toggle (`theme-toggle.tsx`) flips the attribute and persists to `localStorage`. The toggle renders both icons and lets CSS on `[data-theme]` pick one, so the prerendered HTML is theme-agnostic and hydration never mismatches. `hooks/use-theme.ts` exposes the current theme via `useSyncExternalStore` over an attribute `MutationObserver` - the attribute is the single runtime source of truth, no provider needed.

All color lives in **one source**: CSS variables in `src/app/globals.css` (HSL channels, so Tailwind's `hsl(var(--token))` and the `/alpha` modifier keep working); the light theme overrides the same token names under `:root[data-theme="light"]`. The categorical chart palette and the diverging severity ramp are also tokens (`--chart-*`, `--severity-*`), with ink-weight light variants. Every text token clears WCAG 2.2 AA (>= 4.5:1) against background and card in both themes, and chart fills hold >= 3:1 (verified with a contrast script at P0 time).

The severity ramp (`red -> orange -> gold -> blue -> grey`) is deliberately **not** red-vs-green, and every severity/coverage indicator in the UI pairs hue with a shape/icon + text label, so nothing depends on color alone (colorblind- and print-safe). Domain severity classes (`.severity-critical`, ...) resolve from the ramp tokens and are theme-aware for free.

One deliberate duplication, reduced at P2: `components/dashboard/charts.tsx` holds the severity ramp as literal hex, one set per theme, because Recharts writes them onto SVG `fill` attributes, where CSS custom properties do not resolve. Those literals mirror the `--severity-*` tokens; `globals.css` is the canonical source and the sets are kept in sync by hand (noted in the file). The categorical `--chart-*` tokens need no mirror anymore: every categorical consumer (tool activity bars, the observability waterfall, the scorecard dot strips) is plain DOM and reads `hsl(var(--chart-N))` directly, so those charts re-theme through CSS alone. Recharts components still re-render on theme flips through `use-theme.ts`.

Both categorical sets are machine-validated, not eyeballed: at P2 they were run through the six palette checks (OKLCH lightness band per mode, chroma floor, adjacent-pair colorblind separation under protanopia/deuteranopia simulation, >= 3:1 contrast on the card surface) and the failing slots were snapped into band holding their hue - dark slots 1/2/5/8 (slot 5 sat at OKLCH L 0.91 against a 0.67 band ceiling, slot 8 read as gray), light slot 8. Worst adjacent pair after the fix: dE 29.9 (dark) / 31.6 (light). The waterfall's 4-slot subset also passes all-pairs separation, since any two node types can touch there.

### Type, texture, motion

Three typographic voices, all self-hosted via `next/font` (no request leaves the page):

- **Hanken Grotesk** (`--font-sans`): body and UI copy.
- **IBM Plex Mono** (`--font-mono`): the telemetry voice - CVE IDs, ports, CVSS / EPSS scores, token counts - with `tabular-nums` so numerals align in columns.
- **Martian Mono** (`--font-display`): the display voice on `h1`/`h2` (base rule in `globals.css`, pages inherit it) and opt-in via the `font-display` utility for verdicts and hero numerals. A wide instrument face, reserved for short strings.

The type scale is perfect-fourth (ratio 1.333) from `text-xl` up, where hierarchy lives; `xs`-`lg` keep Tailwind defaults because the telemetry-dense UI (tables, badges, coverage strips) depends on them.

Texture and motion are token-level primitives in `globals.css`: a monochrome SVG film grain inlined as a data URI overlays the page at 3.5-5% opacity per theme (`--grain-opacity`); `.rule-hairline` and `.scanline-overlay` are the editorial hairline / scanline surfaces (the scanline is reserved for the hero); `.reveal` and `.draw-in` are CSS-only staggered page-load primitives (`--reveal-i` sets the stagger index). All of it is neutralized by the `prefers-reduced-motion` block without per-call-site work.

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

### Re-capturing the demo fixtures

The fixtures in `src/demo/fixtures/*.json` are real SSE captures, re-recorded whenever the report schema grows a user-visible field (they date from whatever backend was live at capture time; a capture predating a field simply lacks it). `scripts/capture_fixtures.py` (repo root) records one fixture per run in the exact committed shape - gallery metadata from CLI args, `decision` read from the captured `final` frame, never hand-typed - and refuses streams that error out or never reach `final`. Recipe:

```bash
make up && make seed        # full stack with a real ANTHROPIC_API_KEY
python scripts/capture_fixtures.py \
  --query "<the fixture's exact query>" \
  --slug log4shell --cve CVE-2021-44228 \
  --title Log4Shell --subtitle "Apache Log4j JNDI lookup RCE"
```

Captures bill the LLM (sonnet, roughly one triage run each). After re-capturing, diff the `decision` fields against the gallery order in `src/demo/fixtures.ts` (most- to least-urgent): live feeds drift, and a changed verdict may require reordering or updating the subtitle. Then rebuild the demo and re-run the Playwright pass.

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
- **One deliberate dependency exception: `cmdk` + `@radix-ui/react-dialog` (both exact-pinned) for the command palette.** The bias stays "hand-roll small surfaces", but fuzzy ranking plus combobox accessibility plus focus management over 58 mixed nav/action items is where hand-rolling costs more than the dependency. radix-dialog was already in the tree transitively via cmdk; making it direct lets the dialog shell carry a proper hidden `DialogTitle`.

## Decisions log

| Decision | Why | Alternative rejected |
|---|---|---|
| Next.js 15 App Router | Same React/TS stack the target roles cite, plus a built-in API route for the SSE proxy | Vite SPA (no native API route) |
| shadcn-style primitives (Radix + CVA, copied) | Small bundle, design tokens flow into Tailwind via CSS variables | Component libraries (MUI / Mantine) - too heavy, design lock-in |
| Dark-only "Slate Recon" on one token source *(superseded 2026-07-09)* | A security console is dark-first; one tuned palette beats a maintained light/dark pair, and single-source kills the earlier three-way color drift | Catppuccin dual theme + toggle - dev-dotfiles read, colors fragmented across CSS / charts / diagram |
| Dual-theme "Editorial instrument" foundation (reverses dark-only) | The audience reads in both contexts and a light "technical paper" voice fits the report-heavy surfaces; distinctive type (Martian Mono / IBM Plex Mono / Hanken Grotesk) breaks the generic dark-dashboard idiom; the single token source survives the reversal (light overrides the same variables, charts mirror per theme), so the color drift dark-only killed stays dead | Staying dark-only (stock Grafana/Vercel read, no light-context readability); `next-themes` (a dependency for what a 6-line pre-paint script + one `useSyncExternalStore` hook do) |
| Real node waterfall from client-timestamped `node` events | Honest measured timing on a transparency-thesis project; zero backend change | Even-split synthesis by `reasoning_chain` length - fabricated, retired |
| Permalink via URL fragment (`#r=`, gzip+base64url) | Shareable report with no backend, no storage; the fragment never reaches the server | Server-side share links - would require a DB, an ID scheme, and a leak surface |
| Plain Tailwind animations, `prefers-reduced-motion` guard | Type-safe, zero runtime cost, respects the OS motion preference | framer-motion 11.x - TS strict mode conflicts with motion.* + onClick |
| `localStorage` history | Demo scope, no backend persistence needed | Server-side history - would require a DB and auth |
| `fetch()` + ReadableStream for SSE | EventSource does not support POST body; the parser is 50 lines | Vercel AI SDK - wrong protocol shape |
| `output: "standalone"` Docker | ~150 MB image, no separate nginx | Static export - loses the `/api/triage` route (used only for the keyless demo build, where the routes are stashed) |
| `cmdk` command palette, exact-pinned | Fuzzy ranking + combobox a11y over 57 items beats hand-rolling; unstyled, so the design tokens apply untouched | Hand-rolled listbox + filter (a11y/focus surface too large for the payoff); kbar (heavier, animation dep); cmdk's built-in `Command.Dialog` (no `DialogTitle`, trips Radix's a11y console error - dialog shell composed from radix-dialog directly instead) |
| Grounding render = badge + findings-only panel | The wire already carries a bounded assessment (counters + non-supported claims); rendering exactly that keeps the UI honest about what the server verified, and the badge/panel split mirrors the SSVC authority pattern | Raw tool-payload evidence viewer - per-tool payloads never reach the SSE stream by design (bounded payload); shipping them to the browser would be a second provenance channel to secure and size |
| Hero signature = SSVC ladder cycling four real captured verdicts | The ladder is the project's conceptual core and the hero teaches the exact visual language the report speaks (same rung styling as SsvcVerdict); cases, rules and rationales are verbatim from the server-stamped fixtures, so the marketing surface stays as honest as the product; hover/focus pauses, a rung click jumps, prefers-reduced-motion disables the cycle | A staged/fabricated animation (violates the honesty thesis); interactive-only ladder (hides three quarters of the scale by default); keeping the pipeline diagram in the hero (moved to its own "How it works" section, content intact) |
| Guide as hash-driven master-detail (app idiom over document idiom) | The guide was a 7,400px wall of stacked cards; a rail + one-panel-at-a-time layout reads in a single viewport, and driving selection through the URL hash keeps palette commands and deep links working unchanged (rail items are real anchors, so keyboard and focus semantics come free). Content untouched - pure re-layout | Long document + scrollspy TOC (the status quo: scannability does not survive 16 stacked cards); accordions (still tall, weak deep-linking); ARIA tablist (hash navigation IS navigation - nav/anchor semantics are simpler and URL-addressable) |
| Scorecard as tabbed bands where the KPI row IS the tab rail | Same horizontal principle as the guide: five KPI cards double as ARIA tabs (roving tabindex, arrow keys, `?tab=` deep link like the dashboard), so the summary row and the navigation are one control and every band reads in about a viewport. Efficiency became a first-class band: per-case latency/cost dot strips with the p50/p95/mean markers drawn ON the distribution they summarize, plus a per-case table so no value is hover-gated | The five-section column (status quo, ~4 viewports of scroll); a separate tab strip under the KPI row (two controls saying the same thing) |
| Tool usage as single-hue sorted bars, plain DOM | One series over nominal categories is a magnitude comparison: every bar wears slot 1 and the row label carries identity, with counts at the bar end and an explicit "not called" footer. The donut it replaced cycled 8 hues across 10 tools (cycled pairs are indistinguishable under CVD) and asked the reader to compare close angular slices | Donut + color legend (status quo); coloring bars by their value (double-encodes what length already shows) |
| Waterfall segments colored by node type, with a legend | Color follows the entity (prompt / model request / tool calls / final output), so the same phase reads as the same hue across runs; the 4-slot subset passes all-pairs CVD separation because any two node types can touch. 2px surface gaps separate segments instead of borders | Alternating opacity by segment index (status quo: index parity carries no meaning); per-segment hue cycling |
| Chart tokens snapped to the validated palette (P2) | The P0 `--chart-*` sets passed contrast and worst-pair CVD but failed the OKLCH lightness band and chroma floor when actually computed (dark slot 5 at L 0.91, slot 8 below the chroma floor in both themes); colorblind-safety is computable, so it is computed - each failing slot moved in lightness/chroma only, hue held | Trusting the P0 eyeball ("looks balanced"); regenerating the palette from scratch (would repaint series the demo screenshots already teach) |
| Case study as an in-app tour twin of `docs/case_study.md` | The design narrative is the hiring-signal core of the repo and was buried in a GitHub-only .md; the in-app version reuses the guide's hash-driven master-detail (12 panels, one viewport each, same palette/deep-link contract) and adds what a document cannot: every panel ends in a proof row linking the exact source, test, or live surface backing the claim, and the six defense layers render as a navigable strip. The .md stays the long-form essay; the two cross-link rather than duplicate | Rendering the .md verbatim in-app (a 250-line document wall, the idiom the guide refactor just killed); merging the case study into the guide (different job: the guide explains how to drive, the case study argues why the design holds) |
