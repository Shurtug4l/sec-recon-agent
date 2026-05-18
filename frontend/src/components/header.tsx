import { ShieldAlert } from "lucide-react";

import { ThemeToggle } from "@/components/theme-toggle";

export function Header() {
  return (
    <header className="sticky top-0 z-30 border-b border-border bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-14 items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-primary" />
          <span className="font-mono text-sm font-semibold">sec-recon-agent</span>
          <span className="hidden text-xs text-muted-foreground sm:inline">
            · Pydantic AI + MCP security triage
          </span>
        </div>
        <div className="flex items-center gap-2">
          <a
            href="https://github.com/Shurtug4l/sec-recon-agent"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-muted-foreground transition-colors hover:text-foreground"
          >
            GitHub
          </a>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
