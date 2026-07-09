"use client";

import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { useTheme, type Theme } from "@/hooks/use-theme";

// Severity ramp, one hex set per theme. Kept as literal hex here because
// Recharts writes SVG `fill` attributes, where CSS custom properties do not
// resolve. These MIRROR the --severity-* tokens in globals.css; keep them in
// sync per theme (globals.css is the canonical source). useTheme() re-renders
// the chart when <html data-theme> flips. Plain-DOM charts (ToolActivityBars,
// the observability waterfall) consume hsl(var(--chart-*)) directly and need
// no mirror.
const SEVERITY_COLORS: Record<Theme, Record<string, string>> = {
  dark: {
    critical: "#FF5964",
    high: "#FF8A3D",
    medium: "#FFC24B",
    low: "#4CC3FF",
    info: "#8592A6",
  },
  light: {
    critical: "#B2202E",
    high: "#B34E00",
    medium: "#705200",
    low: "#0A66A5",
    info: "#5A6472",
  },
};

const FALLBACK_COLOR: Record<Theme, string> = { dark: "#8592A6", light: "#5A6472" };

export function SeverityBarChart({ data }: { data: Array<{ severity: string; count: number }> }) {
  const { theme } = useTheme();
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart
        accessibilityLayer
        data={data}
        margin={{ top: 8, right: 8, left: -16, bottom: 0 }}
      >
        <XAxis
          dataKey="severity"
          tick={{ fill: "currentColor", fontSize: 11, opacity: 0.7 }}
          stroke="currentColor"
          opacity={0.2}
        />
        <YAxis
          allowDecimals={false}
          tick={{ fill: "currentColor", fontSize: 11, opacity: 0.7 }}
          stroke="currentColor"
          opacity={0.2}
        />
        <Tooltip
          contentStyle={{
            background: "hsl(var(--popover))",
            border: "1px solid hsl(var(--border))",
            borderRadius: "var(--radius)",
            color: "hsl(var(--popover-foreground))",
            fontSize: 12,
          }}
          labelStyle={{ color: "hsl(var(--popover-foreground))", fontWeight: 600 }}
          itemStyle={{ color: "hsl(var(--popover-foreground))" }}
          cursor={{ fill: "hsl(var(--accent))", opacity: 0.3 }}
        />
        {/* Mark spec: thin bars (cap 24px), 4px rounded data-end, square at
            the baseline. The x-axis label carries identity; the severity hue
            is redundant reinforcement, never the only channel. */}
        <Bar dataKey="count" maxBarSize={24} radius={[4, 4, 0, 0]} isAnimationActive={false}>
          {data.map((entry) => (
            <Cell
              key={entry.severity}
              fill={SEVERITY_COLORS[theme][entry.severity] ?? FALLBACK_COLOR[theme]}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// Tool usage is one series over nominal categories (the tools), so every bar
// wears the same slot-1 hue and the row label carries identity: a magnitude
// comparison, not a part-to-whole. This replaced the former donut, which
// cycled 8 hues across 10 tools (indistinguishable pairs under CVD) and asked
// the reader to compare close angular slices. Plain DOM, so the fill reads
// hsl(var(--chart-1)) straight from the theme tokens.
export function ToolActivityBars({ data }: { data: Array<{ tool: string; count: number }> }) {
  const active = data
    .filter((d) => d.count > 0)
    .sort((a, b) => b.count - a.count || a.tool.localeCompare(b.tool));
  const unused = data.filter((d) => d.count === 0).map((d) => d.tool);

  if (active.length === 0) {
    return (
      <div className="flex h-[220px] items-center justify-center text-xs text-muted-foreground">
        No tool calls yet.
      </div>
    );
  }

  const max = active[0].count;
  return (
    <div className="space-y-3">
      <ol className="space-y-2">
        {active.map((d) => (
          <li
            key={d.tool}
            className="grid grid-cols-[9.5rem_1fr_2.5rem] items-center gap-x-3 text-xs"
          >
            <span className="truncate font-mono text-muted-foreground" title={d.tool}>
              {d.tool}
            </span>
            <span className="border-l border-border py-0.5">
              <span
                className="block h-2 rounded-r-[4px] bg-[hsl(var(--chart-1))]"
                style={{ width: `${(d.count / max) * 100}%`, minWidth: "3px" }}
              />
            </span>
            <span className="text-right font-mono tabular-nums text-foreground">{d.count}</span>
          </li>
        ))}
      </ol>
      {unused.length > 0 && (
        <p className="text-[10px] leading-relaxed text-muted-foreground">
          Not called in this history: {unused.join(", ")}.
        </p>
      )}
    </div>
  );
}
