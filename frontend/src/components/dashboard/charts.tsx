"use client";

import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { useTheme, type Theme } from "@/hooks/use-theme";
import { cn } from "@/lib/utils";

// Severity + categorical palette, one set per theme. Kept as literal hex here
// because Recharts writes SVG `fill` attributes, where CSS custom properties
// do not resolve. These MIRROR the --severity-* and --chart-* tokens in
// globals.css; keep them in sync per theme (globals.css is the canonical
// source). useTheme() re-renders the charts when <html data-theme> flips.
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
    medium: "#8F6A00",
    low: "#0A66A5",
    info: "#5A6472",
  },
};

const FALLBACK_COLOR: Record<Theme, string> = { dark: "#8592A6", light: "#5A6472" };

const TOOL_COLORS: Record<Theme, string[]> = {
  dark: [
    "#5CB8EE",
    "#E39A38",
    "#9A5CEA",
    "#E8566E",
    "#ECE87A",
    "#B85E93",
    "#5A78D6",
    "#A89A5E",
  ],
  light: [
    "#2273A8",
    "#B26A08",
    "#7A4BC4",
    "#C23A57",
    "#877D0C",
    "#A63E7C",
    "#4A5FC9",
    "#8A7440",
  ],
};

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
        <Bar dataKey="count" radius={[6, 6, 0, 0]} isAnimationActive={false}>
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

export function ToolsPieChart({ data }: { data: Array<{ tool: string; count: number }> }) {
  const { theme } = useTheme();
  const nonZero = data.filter((d) => d.count > 0);
  if (nonZero.length === 0) {
    return (
      <div className="flex h-[220px] items-center justify-center text-xs text-muted-foreground">
        No tool calls yet.
      </div>
    );
  }
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={nonZero}
          dataKey="count"
          nameKey="tool"
          cx="50%"
          cy="50%"
          outerRadius={80}
          innerRadius={40}
          paddingAngle={2}
          stroke="hsl(var(--background))"
          strokeWidth={2}
        >
          {nonZero.map((entry, i) => (
            <Cell key={entry.tool} fill={TOOL_COLORS[theme][i % TOOL_COLORS[theme].length]} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: "hsl(var(--popover))",
            border: "1px solid hsl(var(--border))",
            borderRadius: "var(--radius)",
            color: "hsl(var(--popover-foreground))",
            fontSize: 12,
          }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function ToolLegend({ data }: { data: Array<{ tool: string; count: number }> }) {
  const { theme } = useTheme();
  const nonZero = data.filter((d) => d.count > 0);
  if (nonZero.length === 0) return null;
  return (
    <ul className="space-y-1.5 text-xs">
      {nonZero.map((entry, i) => (
        <li key={entry.tool} className="flex items-center gap-2">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ background: TOOL_COLORS[theme][i % TOOL_COLORS[theme].length] }}
          />
          <span className="font-mono">{entry.tool}</span>
          <span className={cn("ml-auto tabular-nums text-muted-foreground")}>{entry.count}</span>
        </li>
      ))}
    </ul>
  );
}
