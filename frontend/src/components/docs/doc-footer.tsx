"use client";

import { ArrowLeft, ArrowRight, ArrowUpRight } from "lucide-react";

import { DOCS, type Doc } from "@/lib/docs";
import { cn } from "@/lib/utils";

// Per-doc footer (P10 "docs mesh"): sequential prev/next across the flattened
// corpus order (the same order as the rail) plus a source link, so a reader who
// reaches the bottom of one doc has an in-app way forward instead of a dead end.
// prev/next reuse the page's selectDoc, so they switch in place (no reload) and
// land at the top; the source link opens the raw markdown on GitHub. This is a
// React footer, not part of the sanitized doc HTML, so its links carry the
// basePath through the normal <a>/onNavigate paths.
export function DocFooter({
  doc,
  onNavigate,
}: {
  doc: Doc;
  onNavigate: (slug: string) => void;
}) {
  const idx = DOCS.findIndex((d) => d.slug === doc.slug);
  const prev = idx > 0 ? DOCS[idx - 1] : null;
  const next = idx >= 0 && idx < DOCS.length - 1 ? DOCS[idx + 1] : null;

  return (
    <div className="mt-12 border-t border-border pt-6">
      <nav aria-label="Adjacent documents" className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {prev ? (
          <AdjacentLink dir="prev" doc={prev} onNavigate={onNavigate} />
        ) : (
          <span className="hidden sm:block" aria-hidden="true" />
        )}
        {next ? (
          <AdjacentLink dir="next" doc={next} onNavigate={onNavigate} />
        ) : (
          <span className="hidden sm:block" aria-hidden="true" />
        )}
      </nav>

      <div className="mt-6 flex items-center justify-between border-t border-border/60 pt-4 text-xs">
        <a
          href={doc.githubUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-muted-foreground transition-colors hover:text-foreground"
        >
          View source on GitHub
          <ArrowUpRight className="h-3 w-3" />
        </a>
        <button
          type="button"
          onClick={() => {
            const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
            window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
          }}
          className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground transition-colors hover:text-foreground"
        >
          Back to top
        </button>
      </div>
    </div>
  );
}

function AdjacentLink({
  dir,
  doc,
  onNavigate,
}: {
  dir: "prev" | "next";
  doc: Doc;
  onNavigate: (slug: string) => void;
}) {
  const isNext = dir === "next";
  return (
    <button
      type="button"
      onClick={() => onNavigate(doc.slug)}
      className={cn(
        "group flex flex-col gap-1 rounded-md border border-border p-3 transition-colors hover:border-primary/40",
        isNext ? "sm:items-end sm:text-right" : "items-start text-left",
      )}
    >
      <span className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        {!isNext && <ArrowLeft className="h-3 w-3" aria-hidden="true" />}
        {isNext ? "Next" : "Previous"}
        {isNext && <ArrowRight className="h-3 w-3" aria-hidden="true" />}
      </span>
      <span className="text-sm font-medium text-foreground group-hover:text-primary">
        {doc.navLabel}
      </span>
    </button>
  );
}
