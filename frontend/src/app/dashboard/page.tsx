"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Activity, BarChart3, Eye } from "lucide-react";

import { Header } from "@/components/header";
import { ObservabilityTab } from "@/components/dashboard/observability-tab";
import { StatisticsTab } from "@/components/dashboard/statistics-tab";
import { TransparencyTab } from "@/components/dashboard/transparency-tab";
import { useTriage } from "@/hooks/use-triage";
import { cn } from "@/lib/utils";

type Tab = "statistics" | "observability" | "transparency";

const TABS: Array<{ key: Tab; label: string; icon: React.ElementType }> = [
  { key: "statistics", label: "Statistics", icon: BarChart3 },
  { key: "observability", label: "Observability", icon: Activity },
  { key: "transparency", label: "Transparency", icon: Eye },
];

const TAB_KEYS = TABS.map((t) => t.key);

function isTab(value: string | null): value is Tab {
  return value !== null && (TAB_KEYS as string[]).includes(value);
}

export default function DashboardPage() {
  const { entries, state } = useTriage();
  const [tab, setTab] = useState<Tab>("statistics");
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  // Deep-link: hydrate the active tab from ?tab= on mount. Reading the query
  // directly (not useSearchParams) keeps the page statically prerenderable
  // (no Suspense boundary required) while ?tab=observability stays shareable.
  useEffect(() => {
    const fromUrl = new URLSearchParams(window.location.search).get("tab");
    if (isTab(fromUrl)) setTab(fromUrl);
  }, []);

  const selectTab = useCallback((next: Tab) => {
    setTab(next);
    const url = new URL(window.location.href);
    url.searchParams.set("tab", next);
    window.history.replaceState(null, "", url);
  }, []);

  function onTabKeyDown(event: React.KeyboardEvent) {
    const current = TAB_KEYS.indexOf(tab);
    let nextIndex: number;
    switch (event.key) {
      case "ArrowRight":
      case "ArrowDown":
        nextIndex = (current + 1) % TABS.length;
        break;
      case "ArrowLeft":
      case "ArrowUp":
        nextIndex = (current - 1 + TABS.length) % TABS.length;
        break;
      case "Home":
        nextIndex = 0;
        break;
      case "End":
        nextIndex = TABS.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    selectTab(TAB_KEYS[nextIndex]);
    tabRefs.current[nextIndex]?.focus();
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main className="container max-w-6xl flex-1 py-8">
        <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
          <div className="flex flex-col gap-1">
            <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
            <p className="text-sm text-muted-foreground">
              Aggregated stats from your local history, per-run observability, and full transparency
              into the agent&apos;s prompt and tool surface.
            </p>
          </div>
          {state.isRunning && (
            <div className="inline-flex items-center gap-2 rounded-full bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
              </span>
              Triage in progress, running in the background
            </div>
          )}
        </div>

        <div
          role="tablist"
          aria-label="Dashboard sections"
          onKeyDown={onTabKeyDown}
          className="mb-6 flex items-center gap-1 border-b border-border"
        >
          {TABS.map(({ key, label, icon: Icon }, i) => {
            const active = tab === key;
            return (
              <button
                key={key}
                ref={(el) => {
                  tabRefs.current[i] = el;
                }}
                type="button"
                role="tab"
                id={`tab-${key}`}
                aria-selected={active}
                aria-controls={`panel-${key}`}
                tabIndex={active ? 0 : -1}
                onClick={() => selectTab(key)}
                className={cn(
                  "flex items-center gap-2 border-b-2 px-4 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
                  active
                    ? "border-primary text-primary"
                    : "border-transparent text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon className="h-4 w-4" />
                {label}
              </button>
            );
          })}
        </div>

        {TABS.map(({ key }) => (
          <div
            key={key}
            role="tabpanel"
            id={`panel-${key}`}
            aria-labelledby={`tab-${key}`}
            tabIndex={0}
            hidden={tab !== key}
            className="focus-visible:outline-none"
          >
            {tab === key && key === "statistics" && <StatisticsTab entries={entries} />}
            {tab === key && key === "observability" && <ObservabilityTab entries={entries} />}
            {tab === key && key === "transparency" && <TransparencyTab />}
          </div>
        ))}
      </main>
    </div>
  );
}
