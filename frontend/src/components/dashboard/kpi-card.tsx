import type { LucideIcon } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface Props {
  label: string;
  value: string | number;
  hint?: string;
  icon?: LucideIcon;
  accent?: "default" | "critical" | "high" | "success";
}

const accentClass: Record<NonNullable<Props["accent"]>, string> = {
  default: "text-foreground",
  critical: "text-destructive",
  high: "text-warning",
  success: "text-success",
};

export function KpiCard({ label, value, hint, icon: Icon, accent = "default" }: Props) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-1">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              {label}
            </p>
            <p className={cn("text-2xl font-semibold tabular-nums", accentClass[accent])}>
              {value}
            </p>
            {hint && <p className="text-[10px] text-muted-foreground">{hint}</p>}
          </div>
          {Icon && <Icon className="h-5 w-5 shrink-0 text-muted-foreground" />}
        </div>
      </CardContent>
    </Card>
  );
}
