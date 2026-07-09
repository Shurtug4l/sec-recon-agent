"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  BarChart3,
  BookOpen,
  ClipboardCheck,
  FileSearch,
  Home,
  MessageSquare,
  Search,
  ShieldAlert,
} from "lucide-react";

import { useCommandPalette } from "@/components/command-palette";
import { GithubLogo } from "@/components/icons/github-logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/utils";

const TABS = [
  { href: "/", label: "Home", icon: Home, match: (p: string) => p === "/" },
  { href: "/triage", label: "Triage", icon: MessageSquare, match: (p: string) => p.startsWith("/triage") },
  { href: "/dashboard", label: "Dashboard", icon: BarChart3, match: (p: string) => p.startsWith("/dashboard") },
  { href: "/scorecard", label: "Scorecard", icon: ClipboardCheck, match: (p: string) => p.startsWith("/scorecard") },
  { href: "/case-study", label: "Case study", icon: FileSearch, match: (p: string) => p.startsWith("/case-study") },
  { href: "/guide", label: "Guide", icon: BookOpen, match: (p: string) => p.startsWith("/guide") },
];

export function Header() {
  const pathname = usePathname();
  const { openPalette } = useCommandPalette();
  // Set after mount so the prerendered HTML (no kbd) matches the first
  // client render; the platform is only knowable client-side.
  const [modKey, setModKey] = useState<string | null>(null);
  useEffect(() => {
    setModKey(/Mac|iP(hone|ad|od)/.test(navigator.platform) ? "⌘" : "Ctrl");
  }, []);
  return (
    <header className="sticky top-0 z-30 border-b border-border bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-14 items-center justify-between gap-4">
        <Link href="/" className="flex items-center gap-2 shrink-0">
          <ShieldAlert className="h-5 w-5 text-primary" />
          <span className="font-mono text-sm font-semibold">sec-recon-agent</span>
          <span className="hidden text-xs text-muted-foreground md:inline">
            · Pydantic AI + MCP security triage
          </span>
        </Link>
        <nav className="flex items-center gap-1">
          {TABS.map(({ href, label, icon: Icon, match }) => {
            const active = match(pathname);
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
                  active
                    ? "bg-accent text-accent-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </Link>
            );
          })}
          <button
            type="button"
            onClick={openPalette}
            aria-label="Open command palette"
            className="ml-1 inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            <Search className="h-3.5 w-3.5" />
            <span className="hidden md:inline">Search...</span>
            {modKey && (
              <kbd className="hidden rounded border border-border bg-muted px-1.5 font-mono text-[10px] text-muted-foreground md:inline">
                {modKey}K
              </kbd>
            )}
          </button>
          <ThemeToggle />
          <a
            href="https://github.com/Shurtug4l/sec-recon-agent"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub repository"
            className="ml-2 inline-flex items-center justify-center rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            <GithubLogo className="h-4 w-4" />
          </a>
        </nav>
      </div>
    </header>
  );
}
