# Frontend design

Companion to [`docs/design.md`](design.md), focused on the Next.js + React UI in `frontend/`. Covers: component map, state model, SSE wire protocol, theming, build, and the trade-offs that landed differently from the rest of the codebase.

## What it is

A Next.js 15 (App Router) single-page application on React 19 + TypeScript strict + Tailwind. It is the primary interface for the triage agent: the user types a query (free text, a CVE ID, a product description, or Nmap XML), the UI streams the agent's progress as it happens, and renders the final `TriageReport` as a structured card with severity/confidence badges and per-CVE detail.

It is not a thin wrapper around the FastAPI surface; it adds:
- A Next.js-side `/api/triage` proxy that lets the browser talk same-origin (no CORS opened on the backend).
- A `localStorage`-backed history sidebar (last 30 runs).
- A dark/light theme toggle with system-pref fallback.
- Strip + display of the `<UNTRUSTED_CONTENT>...</UNTRUSTED_CONTENT>` markers as a styled quote block, so the operator sees the security fence semantically without raw XML-tag clutter.

## File map

```
frontend/src/
├── app/
│   ├── layout.tsx             # root layout, suppressHydrationWarning for theme class
│   ├── page.tsx               # the one page: form + progress + report + sidebar
│   ├── globals.css            # Tailwind directives + Catppuccin CSS variables
│   └── api/triage/route.ts    # SSE proxy to http://agent-api:8000/v1/triage
│
├── components/
│   ├── header.tsx             # sticky header, project title, theme toggle, GitHub link
│   ├── triage-form.tsx        # textarea + example chips + Triage/Stop buttons
│   ├── progress-stream.tsx    # ordered list of node events with in-flight spinner
│   ├── triage-report-view.tsx # full TriageReport card + per-CVE cards + reasoning chain
│   ├── history-sidebar.tsx    # localStorage-backed run list (lg+ viewports)
│   ├── theme-toggle.tsx       # dark/light toggle, persists in localStorage
│   └── ui/                    # shadcn-style primitives (copied, not imported)
│       ├── button.tsx
│       ├── badge.tsx
│       ├── card.tsx
│       ├── textarea.tsx
│       ├── separator.tsx
│       ├── scroll-area.tsx
│       └── collapsible.tsx
│
├── hooks/
│   ├── use-triage.ts          # agent-run state machine, SSE driver, abort support
│   └── use-history.ts         # localStorage CRUD with quota safety
│
└── lib/
    ├── types.ts               # mirrors src/sec_recon_agent/agent/schema.py
    ├── sse.ts                 # fetch+ReadableStream SSE parser
    └── utils.ts               # cn() class-name merger
```

## State model

Two custom hooks own the page state.

**`useTriage()`** drives a single agent run. State:

```ts
{
  isRunning: boolean
  nodes: string[]           // node class names accumulated as they stream in
  report: TriageReport | null
  error: string | null
  startedAt: number | null
  durationMs: number | null
}
```

API:
- `run(query, onCompleted?)` — starts a new run, aborts any previous in-flight one
- `cancel()` — aborts the current request
- `reset()` — returns to initial state

The hook holds an `AbortController` ref so the user's `Stop` button reliably tears down the in-flight HTTP request.

**`useHistory()`** persists past runs in `localStorage` (key `sec-recon-history`) and caps at 30 entries. Failures on read are swallowed (corrupted storage starts fresh); failures on write are swallowed (quota exceeded does not crash the UI).

The page (`app/page.tsx`) wires them together: on form submit it creates a `HistoryEntry`, calls `add()` to push it onto the sidebar, then `run()` to start the stream, with an `onCompleted` callback that patches the entry with the final report or error.

## SSE wire protocol (frontend ↔ Next.js ↔ FastAPI)

The browser never talks to FastAPI directly. Three hops:

```
Browser            Next.js (/api/triage)          FastAPI (/v1/triage)
   │                       │                              │
   │  POST {"query":...}    │                              │
   │─────────────────────▶  │                              │
   │                       │  POST {"query":...}            │
   │                       │ ─────────────────────────────▶│
   │                       │                              │
   │                       │  text/event-stream chunks    │
   │                       │ ◀──────────────────────────── │
   │  text/event-stream    │                              │
   │ ◀────────────────────  │                              │
```

The Next.js route (`src/app/api/triage/route.ts`) is a passthrough: it reads the upstream `ReadableStream` and returns it as the response body. SSE headers (`Content-Type: text/event-stream`, `Cache-Control: no-cache, no-transform`, `X-Accel-Buffering: no`) are set explicitly so reverse proxies (CDN, nginx) do not buffer the stream.

The browser-side parser (`lib/sse.ts`) uses `fetch()` + `ReadableStream` rather than the built-in `EventSource` API because `EventSource` does not support POST with a body. It buffers until `\n\n` (the SSE frame separator), then splits each frame on newlines and extracts the `event:` and `data:` lines. SSE comment lines (`: ` prefix, used as keepalives) are skipped.

Event payloads emitted by the backend:

```
event: started        data: {"query": "..."}
event: node           data: {"node": "UserPromptNode" | "ModelRequestNode" | "CallToolsNode" | "End"}
event: final          data: TriageReport (full JSON)
event: error          data: {"type": "...", "message": "..."}
```

`node` events are the streaming progress signal. The UI renders one row per event with the friendly label and a spinner on the in-flight (latest) one. When `final` arrives, the report renders below the progress list with a fade-in animation. When `error` arrives, an error card replaces the report.

## Untrusted-content fence rendering

`CVEDetail.description` and similar free-text fields come back from the backend wrapped with `<UNTRUSTED_CONTENT>...</UNTRUSTED_CONTENT>` markers (see `src/sec_recon_agent/mcp_server/security.py` and the threat model in [`design.md`](design.md)).

The frontend strips the markers for display and renders the body inside a `border-l-2 muted` quote block with a small label "NVD description (untrusted vendor text)" above it. The label is the visible signal that the text is vendor-authored; the styling visually de-emphasizes it relative to the agent's own summary. The raw markers are never shown to the operator.

If a field is not fenced (some upstream sources do not have free text), it renders inline like normal copy.

## Theming

Two themes share a single design-token set in `src/app/globals.css`:
- **Light** = Catppuccin Latte (paper-soft backgrounds, mauve primary)
- **Dark**  = Catppuccin Macchiato (deep navy backgrounds, lavender primary)

CSS variables (`--background`, `--foreground`, `--primary`, ...) are defined for both, switched by a `.dark` class on `<html>`. Tailwind reads them via `hsl(var(--background))` in `tailwind.config.ts`. shadcn primitives all reference the same variables, so the entire UI flips theme atomically.

Severity colors are domain-specific and live as utility classes (`.severity-critical`, `.severity-high`, etc.) instead of design tokens — they are semantic to triage, not to the design system.

The `<ThemeToggle>` component reads `localStorage[sec-recon-theme]` on mount, falls back to `prefers-color-scheme`, toggles the `.dark` class on `<html>`, and persists the choice. A pre-mount placeholder avoids hydration mismatch.

## Build

```
Dockerfile (frontend/)
├── deps stage     : node:22-alpine + npm install --legacy-peer-deps
├── builder stage  : npm run build  (produces .next/standalone)
└── runtime stage  : node:22-alpine + curl + tini + non-root `node` user
                    Copies only .next/standalone and .next/static
                    Healthcheck: curl GET /
                    PID 1: tini  ·  CMD: node server.js
```

`output: "standalone"` in `next.config.mjs` is the load-bearing piece: it produces a self-contained runtime bundle so the final image does not need `node_modules` or the entire source tree, only ~150 MB of compiled assets.

`--legacy-peer-deps` papers over Next 15's peer-range on the React 19 RC tag; Next 15.x supports React 19 GA at runtime but the package.json range is pinned to an RC string. Future Next minors should make this flag unnecessary.

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

## Decisions log

| Decision | Why | Alternative rejected |
|---|---|---|
| Next.js 15 App Router | Same React/TS the Etiqa ad cites, plus a built-in API route for the SSE proxy | Vite SPA (no native API route) |
| shadcn-style primitives (Radix + CVA, copied) | Small bundle, design tokens flow into Tailwind, easy Catppuccin theming | Component libraries (MUI / Mantine) — too heavy, design lock-in |
| Plain Tailwind animations | Type-safe, zero runtime cost | framer-motion 11.x — TS strict mode conflicts with motion.* + onClick |
| `localStorage` history | Demo scope, no backend persistence needed | Server-side history — would require a DB and auth |
| `fetch()` + ReadableStream for SSE | EventSource does not support POST body; the parser is 50 lines | Vercel AI SDK — wrong protocol shape |
| `output: "standalone"` Docker | ~150 MB image, no separate nginx | Static export — loses the `/api/triage` route |
