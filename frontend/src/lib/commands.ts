import type { ElementType } from "react";
import type { useRouter } from "next/navigation";
import {
  BarChart3,
  BookOpen,
  Braces,
  ClipboardCheck,
  Download,
  ExternalLink,
  Home,
  MessageSquare,
  Play,
  Printer,
  Share2,
  ShieldCheck,
  Terminal,
} from "lucide-react";

import { GithubLogo } from "@/components/icons/github-logo";
import { DEMO_FIXTURES } from "@/demo/fixtures";
import { loadAgentMeta } from "@/lib/agent-meta";
import { SECTIONS } from "@/lib/guide-data";
import { downloadJson, downloadMarkdown, reportToMarkdown } from "@/lib/markdown-export";
import { DASHBOARD_TAB_EVENT } from "@/lib/nav-events";
import { buildPermalink } from "@/lib/permalink";
import type { TriageReport } from "@/lib/types";

// Static command registry for the Cmd+K palette. Commands are built once at
// module scope; anything context-dependent (report availability, current
// route) gates through `visible(ctx)` / branches inside `run(ctx)` instead of
// conditional construction, so cmdk sees a stable item set to filter.

export type CommandGroupName =
  | "Report actions"
  | "Pages"
  | "Dashboard"
  | "Run a triage"
  | "Guide sections"
  | "References"
  | "Project";

// Render order; report actions lead when a report is on screen.
export const GROUP_ORDER: CommandGroupName[] = [
  "Report actions",
  "Pages",
  "Dashboard",
  "Run a triage",
  "Guide sections",
  "References",
  "Project",
];

export interface CommandCtx {
  router: ReturnType<typeof useRouter>;
  // usePathname() value; basePath-stripped, so comparisons are host-agnostic.
  pathname: string;
  // The report currently displayed (live run or selected history entry).
  report: TriageReport | null;
  // The query that produced it; feeds the markdown export header.
  query: string | undefined;
  runTriage: (query: string) => void;
}

export interface PaletteCommand {
  id: string;
  label: string;
  group: CommandGroupName;
  // Extra fuzzy-match aliases fed to cmdk alongside the label.
  keywords?: string[];
  icon?: ElementType;
  // Right-aligned mono hint (hostname, CVE id, file extension).
  hint?: string;
  visible?: (ctx: CommandCtx) => boolean;
  run: (ctx: CommandCtx) => void | Promise<void>;
}

function openExternal(url: string): void {
  window.open(url, "_blank", "noopener,noreferrer");
}

function hostnameOf(href: string): string {
  return new URL(href).hostname.replace(/^www\./, "");
}

function prefersReducedMotion(): boolean {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

// Same filename stamp as the report-view export buttons.
function exportStamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
}

const hasReport = (ctx: CommandCtx): boolean => ctx.report !== null;

const REPORT_ACTIONS: PaletteCommand[] = [
  {
    id: "report:copy-link",
    label: "Copy shareable report link",
    group: "Report actions",
    keywords: ["share", "permalink", "url"],
    icon: Share2,
    visible: hasReport,
    run: async ({ report }) => {
      if (!report) return;
      // buildPermalink returns null for oversized reports; without a toast
      // surface the palette stays silent, same accepted tradeoff as closing
      // before the clipboard write resolves.
      const url = await buildPermalink(report, window.location.origin);
      if (url) await navigator.clipboard.writeText(url);
    },
  },
  {
    id: "report:export-md",
    label: "Export report as Markdown",
    group: "Report actions",
    keywords: ["download", "markdown"],
    icon: Download,
    hint: ".md",
    visible: hasReport,
    run: ({ report, query }) => {
      if (!report) return;
      downloadMarkdown(`triage-${exportStamp()}.md`, reportToMarkdown(report, query));
    },
  },
  {
    id: "report:export-json",
    label: "Export report as JSON",
    group: "Report actions",
    keywords: ["download", "raw", "machine-readable"],
    icon: Braces,
    hint: ".json",
    visible: hasReport,
    run: ({ report }) => {
      if (!report) return;
      downloadJson(`triage-${exportStamp()}.json`, JSON.stringify(report, null, 2));
    },
  },
  {
    id: "report:export-pdf",
    label: "Export report as PDF",
    group: "Report actions",
    keywords: ["print", "download"],
    icon: Printer,
    hint: "print",
    // The @media print stylesheet targets #printable-report, which is in the
    // DOM only where TriageReportView is mounted.
    visible: (ctx) => hasReport(ctx) && (ctx.pathname === "/triage" || ctx.pathname === "/r"),
    run: () => window.print(),
  },
  {
    id: "report:show-grounding",
    label: "Show grounding verification",
    group: "Report actions",
    keywords: ["provenance", "claims", "verified", "hallucination", "evidence"],
    icon: ShieldCheck,
    // #grounding-section exists only where TriageReportView is mounted and the
    // report carries a grounding assessment (absent on pre-grounding history).
    visible: (ctx) =>
      !!ctx.report?.grounding && (ctx.pathname === "/triage" || ctx.pathname === "/r"),
    run: () => {
      document.getElementById("grounding-section")?.scrollIntoView({
        behavior: prefersReducedMotion() ? "auto" : "smooth",
        block: "start",
      });
    },
  },
];

// Mirrors the header TABS list (labels, icons, order). Kept local: importing
// header.tsx here would create a module cycle through the palette provider.
const PAGES: PaletteCommand[] = [
  { href: "/", label: "Home", icon: Home, keywords: ["landing", "start"] },
  { href: "/triage", label: "Triage", icon: MessageSquare, keywords: ["run", "query", "console"] },
  { href: "/dashboard", label: "Dashboard", icon: BarChart3, keywords: ["metrics", "charts"] },
  { href: "/scorecard", label: "Scorecard", icon: ClipboardCheck, keywords: ["eval", "golden", "redteam"] },
  { href: "/guide", label: "Guide", icon: BookOpen, keywords: ["glossary", "docs", "help"] },
].map(({ href, label, icon, keywords }) => ({
  id: `page:${href}`,
  label: `Go to ${label}`,
  group: "Pages" as const,
  keywords,
  icon,
  run: ({ router }: CommandCtx) => router.push(href),
}));

const DASHBOARD_TABS: PaletteCommand[] = [
  { key: "statistics", label: "Statistics", keywords: ["stats", "charts", "kpi", "severity"] },
  { key: "observability", label: "Observability", keywords: ["waterfall", "tokens", "cost", "latency", "usage"] },
  { key: "transparency", label: "Transparency", keywords: ["system prompt", "tools", "model", "meta"] },
].map(({ key, label, keywords }) => ({
  id: `dashboard:${key}`,
  label: `Dashboard: ${label}`,
  group: "Dashboard" as const,
  keywords,
  icon: BarChart3,
  run: ({ router, pathname }: CommandCtx) => {
    if (pathname === "/dashboard") {
      // Already mounted: rewrite ?tab= the same way the page's own tablist
      // does, then nudge its sync effect. router.push would remount.
      const url = new URL(window.location.href);
      url.searchParams.set("tab", key);
      window.history.replaceState(null, "", url);
      window.dispatchEvent(new Event(DASHBOARD_TAB_EVENT));
    } else {
      router.push(`/dashboard?tab=${key}`);
    }
  },
}));

// Works in both build modes: use-triage.run() matches demo fixtures
// internally and replays the capture; live mode streams the same query.
const TRIAGE_RUNS: PaletteCommand[] = DEMO_FIXTURES.map((f) => ({
  id: `triage:${f.slug}`,
  label: `Run triage: ${f.title}`,
  group: "Run a triage" as const,
  keywords: [f.cve, f.slug, f.decision],
  icon: Play,
  hint: f.cve,
  run: ({ router, runTriage }) => {
    router.push("/triage");
    runTriage(f.query);
  },
}));

const GUIDE_SECTIONS: PaletteCommand[] = SECTIONS.map((s) => ({
  id: `guide:${s.id}`,
  label: `Guide: ${s.title}`,
  group: "Guide sections" as const,
  keywords: [s.shortLabel, s.badge, s.id],
  icon: s.icon,
  run: ({ router, pathname }) => {
    if (pathname === "/guide") {
      // The guide is a master-detail: the panel is hash-driven, so setting
      // the hash directly fires the page's hashchange listener and selects
      // the section (same-route router.push on a hash is historically flaky
      // in the App Router; this bypasses the router entirely).
      window.location.hash = s.id;
    } else {
      router.push(`/guide#${s.id}`);
    }
  },
}));

const REFERENCES: PaletteCommand[] = SECTIONS.flatMap((s) =>
  s.refs.map((r) => ({
    id: `ref:${r.href}`,
    label: r.label,
    group: "References" as const,
    keywords: [s.shortLabel, s.title],
    icon: ExternalLink,
    hint: hostnameOf(r.href),
    run: () => openExternal(r.href),
  })),
);

const PROJECT: PaletteCommand[] = [
  {
    id: "project:github",
    label: "Open GitHub repository",
    group: "Project",
    keywords: ["source", "code", "repo"],
    icon: GithubLogo,
    hint: "github.com",
    run: () => openExternal("https://github.com/Shurtug4l/sec-recon-agent"),
  },
  {
    id: "project:copy-system-prompt",
    label: "Copy system prompt",
    group: "Project",
    keywords: ["transparency", "meta", "prompt"],
    icon: Terminal,
    run: async () => {
      try {
        const meta = await loadAgentMeta();
        await navigator.clipboard.writeText(meta.system_prompt);
      } catch {
        // No toast surface; a failed fetch (live mode, backend down) stays
        // silent rather than throwing into the void after the palette closed.
      }
    },
  },
];

export const COMMANDS: PaletteCommand[] = [
  ...REPORT_ACTIONS,
  ...PAGES,
  ...DASHBOARD_TABS,
  ...TRIAGE_RUNS,
  ...GUIDE_SECTIONS,
  ...REFERENCES,
  ...PROJECT,
];
