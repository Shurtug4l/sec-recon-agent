# Frontend design

Companion to [`docs/design.md`](design.md), focused on the Next.js + React UI in `frontend/`. Covers: component map, state model, SSE wire protocol, theming, build, and the trade-offs that landed differently from the rest of the codebase.

## What it is

A Next.js 15 (App Router) application on React 19 + TypeScript strict + Tailwind, with eight routes: `/` (landing), `/triage` (form + report), `/dashboard` (statistics / observability / transparency / audit trail), `/scorecard` (the sonnet-baseline scorecard rendered statically from committed result JSONs), `/case-study` (the design narrative as a guided tour, twin of `docs/case_study.md`), `/docs` (the project's own markdown documentation rendered in-app, master-detail with cross-doc search), `/guide` (framework explainer), and `/r` (a self-contained shared-report viewer, not in the nav). The header nav carries seven tabs: Home, Triage, Dashboard, Scorecard, Case study, Docs, Guide (labels collapse to icon-only below `md` so the row fits a phone). It is the primary interface for the triage agent: the user types a query (free text, a CVE ID, a product description, or Nmap XML), the UI streams the agent's progress as it happens, and renders the final `TriageReport` as a structured card - the deterministic SSVC verdict (SSVC is CISA's remediation-urgency methodology: one of Act / Attend / Track* / Track, computed server-side, never by the LLM), per-feed signal coverage (whether each external feed returned data, had no entry, or errored), severity/confidence, and per-CVE detail.

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
│   ├── dashboard/page.tsx       # ARIA tablist: statistics / observability / transparency / audit
│   ├── scorecard/page.tsx       # scorecard shell (title + provenance) around the tabbed bands
│   ├── case-study/page.tsx      # design-narrative tour: hash-driven rail, 12 panels, 6-layer strip
│   ├── docs/page.tsx            # in-app docs: doc rail + rendered panel + on-page TOC + search
│   ├── guide/page.tsx           # master-detail explainer: hash-driven rail + one panel at a time
│   ├── r/page.tsx               # shared-report viewer: decodes a report from the URL fragment
│   ├── globals.css              # Tailwind directives + the dual-theme CSS-variable tokens
│   └── api/
│       ├── triage/route.ts      # SSE proxy to http://agent-api:8000/v1/triage
│       ├── meta/route.ts        # proxy to /v1/meta (transparency view)
│       └── audit/route.ts       # proxy to /v1/audit (audit-trail view)
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
│   ├── ssvc-decision-trace.tsx  # static mirror of the 8 ssvc.py rules, fired rule lit up
│   ├── provenance-note.tsx      # three-lane authority note (deterministic / model / feed)
│   ├── history-sidebar.tsx      # localStorage-backed run list (lg+ viewports)
│   ├── icons/github-logo.tsx    # inline SVG (lucide v1 dropped brand icons)
│   ├── dashboard/               # kpi-card, charts (Recharts severity bars + plain-DOM tool bars),
│   │                            #   statistics / observability / transparency / audit-trail tabs
│   ├── scorecard/               # scorecard-bands: the KPI row as an ARIA tab rail + five band panels
│   ├── docs/doc-content.tsx     # renders a doc's built HTML + lazy client-side mermaid (memo'd)
│   └── ui/                      # shadcn-style primitives (copied, not imported):
│                                #   button, badge, card, textarea, separator, scroll-area,
│                                #   collapsible, skeleton, command (cmdk + radix-dialog shell),
│                                #   tooltip (radix-tooltip + InfoTip; replaces title= on the
│                                #     load-bearing glosses)
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
    ├── permalink.ts             # gzip+base64url a {query, report} envelope into a URL fragment
    ├── commands.ts              # static 61-command registry for the palette
    ├── guide-data.ts            # guide SECTIONS (sections + external refs), shared with the palette
    ├── audit.ts                 # loads /v1/audit (demo audit.json snapshot or /api/audit proxy)
    ├── docs.ts                  # typed access to the built docs corpus (groups, sections, lookup)
    ├── docs-search.ts           # dependency-free client search over the docs corpus
    ├── docs-generated.json      # GENERATED by scripts/gen-docs.mjs from docs/*.md (do not hand-edit)
    ├── agent-meta.ts            # /v1/meta loader (demo snapshot or proxy fetch)
    ├── nav-events.ts            # cross-component window events (dashboard tab sync, ssvc trace)
    └── utils.ts                 # cn() class-name merger
```

`scripts/gen-docs.mjs` (build-time, dev-only deps) turns `docs/*.md` into
`lib/docs-generated.json`; see [In-app documentation](#in-app-documentation).

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

## Glass-box triage (P8)

Four additions make the report explain itself rather than assert a verdict:

- **SSVC decision trace** (`ssvc-decision-trace.tsx`, a `Show decision trace` disclosure under the verdict, closed by default). A static mirror of the eight first-match-wins rules in `agent/ssvc.py::decide_for_signals`, in evaluation order, each with its plain-language condition and the mono predicate that guards it. The fired rule (`ssvc.rule`) is lit up as `matched`; the rules above it read `not matched` (evaluated, condition false) and the rules below read `not reached` (first-match short-circuits before them). That turns an opaque `rule: high-severity-no-exploitation` into the actual path the engine walked for the driving CVE. The table is a deliberate duplicate of the backend rules (same convention as the hero's `CASES` and the report's `SSVC_ORDER`): a comment names `agent/ssvc.py` as the authority, and a new or reordered rule there must update this table. When `ssvc.rule` is the `no-cves` sentinel, every rule reads `not evaluated` and a note explains the default-Track fall-through.
- **Provenance note** (`provenance-note.tsx`, a `Provenance` disclosure before the reasoning chain). Three lanes stating who authored what: **deterministic** (SSVC verdict, grounding verification - fixed code stamped after the model returns), **model-authored** (summary, recommended action, confidence, reasoning chain - the LLM, constrained to the typed schema and grounded in the tool returns), **external feed data** (CVE/CVSS/CWE, KEV+EPSS, exploit signals, ATT&CK, verbatim from the feeds, free text fenced). The closing line is the injection-resistance thesis: a prompt injection that fully persuades the model still cannot move the verdict from Act to Track, because the model does not hold that pen - the deterministic lane does. The same note ships in the Markdown export.
- **Radix tooltips** (`ui/tooltip.tsx`: `Tooltip` + `InfoTip`, mounted once via `TooltipProvider` in `providers.tsx`). The load-bearing glosses - the `deterministic · server-computed` chip, the grounding badge, the coverage feeds, the confidence-vs-grounding distinction - moved off the native `title=` attribute (invisible to keyboard and touch, unstyled, browser-truncated) onto an accessible tooltip with a focusable trigger, ESC-dismiss, and content that wraps in the design tokens. The dense per-CVE badge titles stay on `title=` deliberately (numerous, inline, tolerable) - the conversion is scoped to the trust cluster, not exhaustive.
- **Report -> guide bridges.** Each signal-coverage feed chip is a link to the guide section that explains it (`kev -> #kev`, `epss -> #epss`, `nvd`/`semantic_search -> #cve-nvd`, `osv -> #osv`, `attack -> #attack`; `exploit` has no dedicated section, so no link) with the gloss in its tooltip; the CVEs and ATT&CK headers carry `What is...` links too. A live signal is one click from its background.

## Report export and share

Every report card carries three exports plus a share link, all client-side with zero new dependencies:

- **Export .md** builds a Markdown document (severity / confidence header, summary, recommended action, per-CVE details with KEV / ransomware / EPSS, ATT&CK techniques with mitigations, the grounding verification, the full reasoning chain) and triggers a browser download (`lib/markdown-export.ts`). No backend route.
- **Raw JSON** downloads the `TriageReport` as returned, verdict and coverage included.
- **Export PDF** calls `window.print()` with an `@media print` stylesheet in `globals.css` that scopes visibility to the report block, hides the chrome, and forces an A4 light-on-white layout; the user picks "Save as PDF" in the system dialog. Native multi-page.
- **Copy link** gzip-encodes a `{v, query, report}` envelope into the URL fragment (`lib/permalink.ts`); `/r` decodes it locally and shows the originating query above the report (P8), so a shared verdict carries what was asked. The decode is backward-compatible: a pre-envelope link (a bare `TriageReport`) is detected by shape and still renders, without a query block. The query is capped (`SHARED_QUERY_MAX`, truncation marked) so a large SBOM/Nmap query never sinks an otherwise-shareable report. The fragment never reaches a server; past the size cap the whole link falls back to suggesting the JSON export. The minted URL is basePath-aware (`NEXT_PUBLIC_BASE_PATH`), so links copied on the Pages demo point inside the project sub-path.

## Command palette

`Cmd+K` (macOS) / `Ctrl+K` (elsewhere), or the Search button in the header, opens a command palette with 61 commands in 7 groups: report actions (copy link, export .md / JSON / PDF, show grounding verification, show SSVC decision trace - visible only while a report is on screen, PDF / grounding / trace only where the report view is in the DOM; the trace command dispatches a window event so the closed-by-default disclosure opens and scrolls), page navigation (including Docs), dashboard tab jumps (including the audit trail), the 7 demo triage runs (live mode submits the same query to the real backend), the 12 guide sections, the guide's 23 external references, and project actions (GitHub, copy system prompt). Section-level search inside the docs is deliberately the `/docs` page's own search box, not palette commands, so the command count stays bounded.

The registry is a static module (`lib/commands.ts`); context-dependent commands gate through a `visible(ctx)` predicate rather than conditional construction, so the filter always sees a stable item set. Section and reference commands consume the same `lib/guide-data.ts` the guide page renders from - one source, no drift. The binding is platform-split on purpose: registering `Ctrl+K` on macOS too would hijack readline kill-line inside the triage textarea.

Fuzzy matching and combobox accessibility come from `cmdk`; the dialog shell is composed from `@radix-ui/react-dialog` directly (see the decisions log for why not cmdk's built-in dialog).

## In-app documentation

The `/docs` route renders the project's own markdown documentation (`docs/*.md`) inside the app, in the same design system, with cross-document search. The heavy lifting happens at **build time**, not in the browser: `frontend/scripts/gen-docs.mjs` turns each markdown file into `lib/docs-generated.json` through a `unified` pipeline (GFM tables, `rehype-slug` heading anchors, `rehype-highlight` syntax highlighting, a `rehype-sanitize` allowlist, plus two local plugins that swap ` ```mermaid ` fences for `.docs-mermaid` placeholders and wrap tables in horizontal-scroll containers). It also extracts a title, a purpose blurb, and a per-section index (heading id + prose) used by search. Every one of those dependencies is a **devDependency**, so the client ships no markdown parser and no highlighter - only the generated HTML.

The generator's output is a pure function of the docs (no timestamps), and it is committed: the frontend Docker build context is `frontend/` only, so `../docs` is absent there and the build reuses the committed JSON. Where `docs/` *is* present (local dev, CI, the Pages build) `prebuild` / `predev` / `build:demo` regenerate it, and a CI step (`ci-frontend.yml`) regenerates and `git diff --exit-code`s the JSON to fail on drift.

The page (`app/docs/page.tsx`) is a three-column master-detail: a grouped document rail (a horizontal chip row below `lg`), the rendered panel, and an on-page table of contents (`xl+`) with `IntersectionObserver` scroll-spy. `?doc=<slug>` deep-links a document and `#<heading-id>` a section; search runs client-side over the section index (`lib/docs-search.ts`, no fuzzy-search dependency) and a hit navigates to the document and scrolls to the section.

`components/docs/doc-content.tsx` renders one document's built HTML via `dangerouslySetInnerHTML` (first-party content, sanitized at build time) and, only on documents that carry diagrams, lazily `import()`s **mermaid** to render the `.docs-mermaid` blocks - the one client-side dependency the feature adds, code-split onto this route and themed to the active theme (re-rendered on toggle, the source stashed in `data-mermaid-src` so a re-render re-parses the original). The component is `memo`'d deliberately: the SVGs are injected imperatively, outside React, so an unmemoized parent re-render (every scroll-spy tick) would re-apply `dangerouslySetInnerHTML` and wipe them.

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

## Accessibility and responsive (P6)

The whole surface is audited against WCAG 2.2 AA with axe-core across every route and dashboard/scorecard tab, in both themes, at desktop (1280) and phone (390) widths - zero violations. The load-bearing pieces:

- **Header is the responsive spine.** Seven routes never fit a phone bar inline, and turning the labels on at `md` (the old behavior) blew the intrinsic header width past every viewport from 768 to ~1196 px, so the whole tablet/small-laptop band scrolled sideways on every page. Now the labelled tabs live inline from `lg` up (the long product subtitle appears only at `xl`), and below `lg` they collapse behind a disclosure menu: a non-modal dropdown (Escape and outside-click close it, navigation closes it, focus returns to the trigger) listing the same seven routes. Body overflow is zero from 360 to 1280.
- **Dashboard tabs collapse to icon-only below `sm`** (each keeps its label as the `aria-label`), so the four-tab rail fits a phone without a hidden scroll rail.
- **Contrast fixes, all computed not eyeballed.** Light `--severity-medium` was darkened (`#8F6A00` -> `#705200`) because the tinted severity chip sat at ~3.8:1 on card/muted; the syntax-highlight tokens that map onto the chart palette get a light-theme override for the two hues that clear the 3:1 graphics floor but not the 4.5:1 text floor; mermaid edge labels are re-plated on the card token so they hold AA on both diagram backgrounds. Inline prose links carry a persistent underline (color alone is not a sufficient signal, WCAG 1.4.1).
- **Keyboard reach.** A "Skip to content" link (first focusable element) targets `#main-content` on every page; every scrollable region with no focusable child - the system-prompt `<pre>`, the audit/scorecard table wrappers, and the generated docs code blocks / tables / diagrams (`tabIndex` injected in `gen-docs.mjs`) - is itself focusable so a mouseless reader can scroll it (WCAG 2.1.1), with a visible focus ring.
- **State semantics.** Async load failures announce via `role="alert"`; the observability run list and the history sidebar mark the selected entry with `aria-pressed`; loading uses `aria-busy` skeletons with an `sr-only` label. Empty, loading, disabled and error states already covered triage, the four dashboard tabs and the scorecard; P6 made them announce.
- **Report-open state (extended in P8).** P6 audited `/triage` empty, so the report card's dense muted text and its collapsibles were never measured. P8's glass-box work audited the report with the decision trace and provenance note expanded and cleared the pre-existing debt it surfaced: several `text-muted-foreground/70` captions and the inactive SSVC ladder stops (`/50`) failed 4.5:1 on the tinted `/50` panel backgrounds - fixed by moving inset panels to a solid `bg-background` and dropping the sub-full opacities (avoiding the alpha-stacking that compounded a `not reached` row to 1.95:1); the tightly-stacked ATT&CK mitigation links (36x16 px) failed target-size 2.5.8 - fixed to a 24 px min target. Zero axe violations at 1280 in both themes with the report open.

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
- **One deliberate dependency exception: `cmdk` + `@radix-ui/react-dialog` (both exact-pinned) for the command palette.** The bias stays "hand-roll small surfaces", but fuzzy ranking plus combobox accessibility plus focus management over 59 mixed nav/action items is where hand-rolling costs more than the dependency. radix-dialog was already in the tree transitively via cmdk; making it direct lets the dialog shell carry a proper hidden `DialogTitle`.

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
| Docs rendered from `docs/*.md` at build time, not client-side (P5) | The whole markdown -> sanitized HTML + syntax-highlight pipeline runs in Node with dev-only deps, so the browser ships no parser and no highlighter; the generated JSON is a pure function of the docs, committed (the Docker context lacks `../docs`) and CI-gated for freshness. Doc-level master-detail with an on-page section TOC honors the horizontal principle at the navigation level, while a reference doc is allowed to scroll inside its own panel | Client-side `react-markdown` (ships the parser + raw markdown to every reader); exploding each doc into one-section-per-panel (fragments continuous prose - design.md's decisions log would be 30 panels); a searchable index that links out to GitHub (the user chose in-app rendering, and GitHub is one click away anyway) |
| Mermaid the only added client dependency, code-split + lazy | Diagrams (design.md) must render in-app; mermaid is imported only on `/docs` and only when a diagram block is present, so its weight never touches the other routes; it renders themed and re-renders on toggle. `DocContent` is `memo`'d because the SVGs are injected imperatively - an unmemoized re-render (every scroll-spy tick) re-applies `dangerouslySetInnerHTML` and wipes them | Build-time SVG pre-render via mermaid-cli (needs puppeteer in CI - heavy and fragile, and dual-theme means two committed SVGs per diagram that drift from source); showing mermaid blocks as raw code (ugly, defeats the point); a heavier diagram lib |
| `rehype-sanitize` allowlist over first-party doc HTML | Defense in depth on a security-portfolio repo: even our own build-time markdown passes an explicit tag/attribute allowlist before it becomes `dangerouslySetInnerHTML`, so the pattern is safe by construction if a doc ever ingested untrusted content. The clobber-prefix is disabled (clean `#threat-model` anchors) because the ids are ours | Trusting first-party content unsanitized (correct today, but a footgun the day a doc embeds something); a runtime DOM sanitizer (build-time is free and ships nothing) |
| Audit trail as a fourth dashboard tab, fed by `GET /v1/audit` | The hash-chained audit log was CLI-only (`sec-recon-audit`); surfacing it in-app makes the governance record-keeping demonstrable to a reviewer. It lives beside Transparency (its sibling in intent), not a new header tab, and reads in one viewport: a chain-integrity banner (verified N/N, re-checked live) over a digest-only row table with the `prev -> this` hash link visible. The demo loads a real sealed chain from the seven captures (`demo/audit.json`), live proxies `/api/audit` | A dedicated `/audit` route (an eighth header tab, worse on mobile); a raw JSON dump (the chain linkage and the SSVC/grounding signals want a table); recomputing the chain client-side (would mean porting the JCS canonicalization to JS - the server verifies, the UI reports) |
| Header: inline labelled tabs from `lg`, disclosure menu below (P6) | Seven routes plus the search/theme/repo controls cannot fit a phone bar inline, and the previous `md` label breakpoint pushed the intrinsic header to ~1196 px, so 768-1195 px scrolled sideways on every route. A single `lg` cutoff (labels + subtitle tuned to fit 1024, subtitle deferred to `xl`) with a non-modal disclosure below it fixes both broken bands and keeps the command palette as the redundant keyboard path | A horizontally-scrollable tab rail (a hidden scroll rail, the anti-pattern the horizontal principle forbids); icon-only tabs at every width (loses the label affordance desktop has room for); a full modal drawer (focus-trap machinery for a seven-item menu the palette already duplicates) |
| Every scrollable region is keyboard-focusable (P6) | A wide table, code block or diagram that scrolls but has no focusable child traps its hidden content away from a mouseless reader (WCAG 2.1.1). The React scroll wrappers take `tabIndex`/`role="region"` with unique labels; the build-time docs pipeline injects `tabIndex` on the code/table/mermaid containers (allowlisted through `rehype-sanitize`), all with a visible focus ring | Leaving scroll to the mouse (fails 2.1.1); wrapping each in an ARIA landmark (five same-named `region`s per docs page trip landmark-uniqueness - bare `tabIndex` on the generated ones avoids it) |
| SSVC decision trace = static mirror of the backend rules (P8) | The verdict already names its rule; showing the whole first-match ladder with the fired rule lit (and the rules above marked `not matched`, below `not reached`) makes the decision auditable at a glance without moving any logic to the client. The duplication is the honest cost of the deterministic-not-LLM boundary: the Python stays the authority, a comment binds the table to `agent/ssvc.py`, and the eight ids/outcomes are pinned so a backend rule change surfaces here | Fetching a server-rendered trace (the verdict is stamped, not streamed - no round trip exists to add one); deriving the trace from signals in the browser (would re-implement the decision and could drift from Python - the exact bug the deterministic engine exists to avoid); leaving the bare rule id (opaque to anyone who has not read `ssvc.py`) |
| Provenance note = three authored lanes, one injection-resistance line (P8) | The report is not one blob of model output; stating the three authorities (deterministic / model / feed) once, plainly, is the clearest form of the security thesis and costs one collapsible. It names the fields per lane and closes on why a persuaded model still cannot flip Act to Track | A per-field authority badge on every value (visual noise, and the boundary is a property of the pipeline, not each field); burying it in the guide (the claim is about *this* report, so it belongs on the report and in its export) |
| Radix tooltips scoped to the trust cluster, not every `title=` (P8) | The load-bearing glosses (the `deterministic` chip, grounding badge, coverage feeds, confidence-vs-grounding) carry the trust narrative and must be reachable by keyboard and touch, which `title=` is not; converting exactly those, plus an `InfoTip` affordance that makes the explanation *discoverable* (a visible dot, unlike an invisible `title`), is the glass-box win. The ~20 dense per-CVE badge `title=`s stay native - converting all of them bloats the diff and the inline badge row for marginal gain | Converting every `title=` (large diff, denser badge rows, no trust payoff on `affected products`); leaving all glosses on `title=` (fails keyboard/touch on the pieces that carry the argument); a custom tooltip (Radix already solves collision, focus, dismiss, portal) |
| Permalink carries a `{v, query, report}` envelope, backward-compatible (P8) | A shared verdict without the question that produced it is half a report; wrapping the payload in a versioned envelope adds the query while a shape-detecting decode still reads every pre-envelope link. The query is capped and truncation-marked so a large SBOM/Nmap paste degrades the query, not the whole share | Bumping to a new fragment key (`#r2=`) and orphaning old links; embedding the full uncapped query (a big paste would blow the size cap and lose the entire permalink); a separate query fragment param (two things to keep in sync vs one self-describing envelope) |
