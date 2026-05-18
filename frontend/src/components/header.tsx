"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { BarChart3, MessageSquare, ShieldAlert } from "lucide-react";

import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/utils";

export function Header() {
  const pathname = usePathname();
  return (
    <header className="sticky top-0 z-30 border-b border-border bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-14 items-center justify-between">
        <Link href="/" className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-primary" />
          <span className="font-mono text-sm font-semibold">sec-recon-agent</span>
          <span className="hidden text-xs text-muted-foreground sm:inline">
            · Pydantic AI + MCP security triage
          </span>
        </Link>
        <nav className="flex items-center gap-1">
          <Link
            href="/"
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              pathname === "/"
                ? "bg-accent text-accent-foreground"
                : "text-muted-foreground hover:bg-accent hover:text-foreground",
            )}
          >
            <MessageSquare className="h-3.5 w-3.5" />
            Triage
          </Link>
          <Link
            href="/dashboard"
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              pathname === "/dashboard"
                ? "bg-accent text-accent-foreground"
                : "text-muted-foreground hover:bg-accent hover:text-foreground",
            )}
          >
            <BarChart3 className="h-3.5 w-3.5" />
            Dashboard
          </Link>
          <a
            href="https://github.com/Shurtug4l/sec-recon-agent"
            target="_blank"
            rel="noopener noreferrer"
            className="ml-2 text-xs text-muted-foreground transition-colors hover:text-foreground"
          >
            GitHub
          </a>
          <ThemeToggle />
        </nav>
      </div>
    </header>
  );
}
