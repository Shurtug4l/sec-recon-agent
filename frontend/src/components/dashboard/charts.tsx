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

import { cn } from "@/lib/utils";

// Slate Recon severity + categorical palette. Kept as literal hex here because
// Recharts writes SVG `fill` attributes, where CSS custom properties do not
// resolve. These MIRROR the --severity-* and --chart-* tokens in globals.css;
// keep the two in sync (globals.css is the canonical source).
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#FF5964",
  high: "#FF8A3D",
  medium: "#FFC24B",
  low: "#4CC3FF",
  info: "#8592A6",
};

const FALLBACK_COLOR = "#8592A6";

const TOOL_COLORS = [
  "#5CB8EE",
  "#E39A38",
  "#9A5CEA",
  "#E8566E",
  "#ECE87A",
  "#B85E93",
  "#5A78D6",
  "#A89A5E",
];

export function SeverityBarChart({ data }: { data: Array<{ severity: string; count: number }> }) {
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
              fill={SEVERITY_COLORS[entry.severity] ?? FALLBACK_COLOR}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function ToolsPieChart({ data }: { data: Array<{ tool: string; count: number }> }) {
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
            <Cell key={entry.tool} fill={TOOL_COLORS[i % TOOL_COLORS.length]} />
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
  const nonZero = data.filter((d) => d.count > 0);
  if (nonZero.length === 0) return null;
  return (
    <ul className="space-y-1.5 text-xs">
      {nonZero.map((entry, i) => (
        <li key={entry.tool} className="flex items-center gap-2">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ background: TOOL_COLORS[i % TOOL_COLORS.length] }}
          />
          <span className="font-mono">{entry.tool}</span>
          <span className={cn("ml-auto tabular-nums text-muted-foreground")}>{entry.count}</span>
        </li>
      ))}
    </ul>
  );
}
