"use client";

import { useState } from "react";
import { Activity, BarChart3, Eye } from "lucide-react";

import { Header } from "@/components/header";
import { ObservabilityTab } from "@/components/dashboard/observability-tab";
import { StatisticsTab } from "@/components/dashboard/statistics-tab";
import { TransparencyTab } from "@/components/dashboard/transparency-tab";
import { useHistory } from "@/hooks/use-history";
import { cn } from "@/lib/utils";

type Tab = "statistics" | "observability" | "transparency";

const TABS: Array<{ key: Tab; label: string; icon: React.ElementType }> = [
  { key: "statistics", label: "Statistics", icon: BarChart3 },
  { key: "observability", label: "Observability", icon: Activity },
  { key: "transparency", label: "Transparency", icon: Eye },
];

export default function DashboardPage() {
  const { entries } = useHistory();
  const [tab, setTab] = useState<Tab>("statistics");

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main className="container max-w-6xl flex-1 py-8">
        <div className="mb-6 flex flex-col gap-1">
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            Aggregated stats from your local history, per-run observability, and full transparency
            into the agent's prompt and tool surface.
          </p>
        </div>

        <nav className="mb-6 flex items-center gap-1 border-b border-border">
          {TABS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              className={cn(
                "flex items-center gap-2 border-b-2 px-4 py-2 text-sm font-medium transition-colors",
                tab === key
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </nav>

        {tab === "statistics" && <StatisticsTab entries={entries} />}
        {tab === "observability" && <ObservabilityTab entries={entries} />}
        {tab === "transparency" && <TransparencyTab />}
      </main>
    </div>
  );
}
