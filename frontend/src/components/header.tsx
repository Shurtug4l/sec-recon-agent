"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  BarChart3,
  BookOpen,
  Home,
  MessageSquare,
  ShieldAlert,
} from "lucide-react";

import { GithubLogo } from "@/components/icons/github-logo";
import { cn } from "@/lib/utils";

const TABS = [
  { href: "/", label: "Home", icon: Home, match: (p: string) => p === "/" },
  { href: "/triage", label: "Triage", icon: MessageSquare, match: (p: string) => p.startsWith("/triage") },
  { href: "/dashboard", label: "Dashboard", icon: BarChart3, match: (p: string) => p.startsWith("/dashboard") },
  { href: "/guide", label: "Guide", icon: BookOpen, match: (p: string) => p.startsWith("/guide") },
];

export function Header() {
  const pathname = usePathname();
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
                  "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
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
          <a
            href="https://github.com/Shurtug4l/sec-recon-agent"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub repository"
            className="ml-2 inline-flex items-center justify-center rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            <GithubLogo className="h-4 w-4" />
          </a>
        </nav>
      </div>
    </header>
  );
}
