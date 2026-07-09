"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowUpRight, FileText, Search, X } from "lucide-react";

import { DocContent } from "@/components/docs/doc-content";
import { Header } from "@/components/header";
import { Badge } from "@/components/ui/badge";
import { DEFAULT_DOC_SLUG, DOC_GROUPS, getDoc } from "@/lib/docs";
import { searchDocs } from "@/lib/docs-search";
import { cn } from "@/lib/utils";

// Sticky header height (h-14 = 56px) plus breathing room; anchor scrolls land
// the target heading below the header rather than under it.
const HEADER_OFFSET = 80;

export default function DocsPage() {
  const [activeSlug, setActiveSlug] = useState(DEFAULT_DOC_SLUG);
  const [query, setQuery] = useState("");
  const [activeSection, setActiveSection] = useState<string | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  // Section to scroll to after the next doc switch renders (cross-doc search).
  const pendingAnchor = useRef<string | null>(null);

  const doc = getDoc(activeSlug) ?? getDoc(DEFAULT_DOC_SLUG)!;
  const hits = useMemo(() => searchDocs(query), [query]);
  const searching = query.trim().length >= 2;

  // ?doc= is the doc-level deep link; read it on mount and on back/forward.
  useEffect(() => {
    const apply = () => {
      const slug = new URLSearchParams(window.location.search).get("doc");
      if (slug && getDoc(slug)) setActiveSlug(slug);
    };
    apply();
    window.addEventListener("popstate", apply);
    return () => window.removeEventListener("popstate", apply);
  }, []);

  const scrollToId = useCallback((id: string) => {
    const el = document.getElementById(id);
    if (!el) return;
    const y = el.getBoundingClientRect().top + window.scrollY - HEADER_OFFSET;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    window.scrollTo({ top: y, behavior: reduce ? "auto" : "smooth" });
    setActiveSection(id);
  }, []);

  const selectDoc = useCallback(
    (slug: string, sectionId?: string) => {
      pendingAnchor.current = sectionId ?? null;
      setActiveSlug(slug);
      setQuery("");
      setActiveSection(sectionId ?? null);
      const url = new URL(window.location.href);
      url.searchParams.set("doc", slug);
      url.hash = "";
      window.history.replaceState(null, "", url);
      if (!sectionId) window.scrollTo({ top: 0, behavior: "auto" });
    },
    [],
  );

  // Once the switched doc is in the DOM, honor a pending section anchor.
  useEffect(() => {
    if (!pendingAnchor.current) return;
    const id = pendingAnchor.current;
    pendingAnchor.current = null;
    requestAnimationFrame(() => scrollToId(id));
  }, [activeSlug, scrollToId]);

  // Scroll-spy: mark the section nearest the top of the viewport as active so
  // the on-page table of contents tracks the reading position.
  useEffect(() => {
    const root = contentRef.current;
    if (!root) return;
    const heads = Array.from(root.querySelectorAll<HTMLElement>("h2[id], h3[id]"));
    if (heads.length === 0) return;
    const observer = new IntersectionObserver(
      (entries) => {
        const top = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (top) setActiveSection(top.target.id);
      },
      { rootMargin: `-${HEADER_OFFSET}px 0px -68% 0px`, threshold: 0 },
    );
    heads.forEach((h) => observer.observe(h));
    return () => observer.disconnect();
  }, [activeSlug]);

  const toc = doc.sections.filter((s) => s.depth <= 3);

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main className="flex-1">
        <div className="container max-w-7xl py-8">
          <div className="mb-6">
            <Badge variant="secondary" className="mb-3 font-mono text-[10px]">
              Documentation
            </Badge>
            <h1 className="text-3xl font-semibold tracking-tight">Docs</h1>
            <p className="mt-3 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              The project&apos;s engineering, operations, and governance
              documentation, rendered in-app. Pick a document from the rail or
              search across every section; each heading is deep-linkable.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-[248px_minmax(0,1fr)] lg:gap-8 xl:grid-cols-[248px_minmax(0,1fr)_216px]">
            {/* Master rail: search + grouped doc list (lg+), chip row below. */}
            <aside className="lg:sticky lg:top-20 lg:self-start">
              <div className="relative mb-3">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search the docs..."
                  aria-label="Search the documentation"
                  className="w-full rounded-md border border-border bg-card py-1.5 pl-8 pr-8 text-xs outline-none transition-colors placeholder:text-muted-foreground/70 focus:border-primary/50 focus:ring-1 focus:ring-primary/30"
                />
                {query && (
                  <button
                    type="button"
                    onClick={() => setQuery("")}
                    aria-label="Clear search"
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>

              {searching ? (
                <SearchResults hits={hits} onPick={selectDoc} />
              ) : (
                <nav
                  aria-label="Documents"
                  className="flex gap-1.5 overflow-x-auto pb-2 lg:flex-col lg:gap-0 lg:overflow-visible lg:pb-0"
                >
                  {DOC_GROUPS.map((group) => (
                    <div key={group.name} className="contents lg:block">
                      <p className="hidden lg:mb-2 lg:mt-4 lg:block lg:text-[10px] lg:font-semibold lg:uppercase lg:tracking-widest lg:text-muted-foreground lg:first:mt-0">
                        {group.name}
                      </p>
                      {group.docs.map((d) => (
                        <button
                          key={d.slug}
                          type="button"
                          onClick={() => selectDoc(d.slug)}
                          aria-current={d.slug === activeSlug ? "true" : undefined}
                          className={cn(
                            "shrink-0 whitespace-nowrap rounded-full border border-border px-3 py-1.5 text-left text-xs transition-colors",
                            "lg:block lg:w-full lg:rounded-none lg:border-0 lg:border-l-2 lg:px-3 lg:py-1.5",
                            d.slug === activeSlug
                              ? "border-primary bg-primary/10 text-primary lg:border-l-primary lg:bg-transparent"
                              : "text-muted-foreground hover:border-primary/40 hover:text-foreground lg:border-l-transparent lg:hover:border-l-border",
                          )}
                        >
                          {d.navLabel}
                        </button>
                      ))}
                    </div>
                  ))}
                </nav>
              )}
            </aside>

            {/* Detail: doc header + rendered content, keyed remount = fade. */}
            <article key={doc.slug} className="min-w-0 animate-fade-in">
              <div className="mb-5 border-b border-border pb-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 text-primary">
                      <FileText className="h-4 w-4 shrink-0" />
                      <span className="font-mono text-[11px] text-muted-foreground">
                        docs/{doc.slug}.md
                      </span>
                    </div>
                    <h2 className="mt-1.5 text-xl font-semibold tracking-tight">
                      {doc.title}
                    </h2>
                  </div>
                  <a
                    href={doc.githubUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border px-2.5 py-1.5 text-[11px] font-medium text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
                  >
                    GitHub
                    <ArrowUpRight className="h-3 w-3" />
                  </a>
                </div>
                <p className="mt-3 max-w-3xl text-sm leading-relaxed text-muted-foreground">
                  {doc.purpose}
                </p>
              </div>
              <div ref={contentRef}>
                <DocContent doc={doc} />
              </div>
            </article>

            {/* On-page table of contents (xl+), scroll-spy tracked. */}
            <aside className="hidden xl:block">
              <div className="sticky top-20 self-start">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                  On this page
                </p>
                <nav aria-label="On this page" className="flex flex-col border-l border-border">
                  {toc.map((s) => (
                    <a
                      key={s.id}
                      href={`#${s.id}`}
                      onClick={(e) => {
                        e.preventDefault();
                        scrollToId(s.id);
                        const url = new URL(window.location.href);
                        url.hash = s.id;
                        window.history.replaceState(null, "", url);
                      }}
                      className={cn(
                        "-ml-px border-l-2 py-1 text-xs leading-snug transition-colors",
                        s.depth === 3 ? "pl-5" : "pl-3",
                        s.id === activeSection
                          ? "border-l-primary text-primary"
                          : "border-l-transparent text-muted-foreground hover:border-l-border hover:text-foreground",
                      )}
                    >
                      {s.title}
                    </a>
                  ))}
                </nav>
              </div>
            </aside>
          </div>
        </div>
      </main>
    </div>
  );
}

function SearchResults({
  hits,
  onPick,
}: {
  hits: ReturnType<typeof searchDocs>;
  onPick: (slug: string, sectionId?: string) => void;
}) {
  if (hits.length === 0) {
    return (
      <p className="px-1 py-4 text-xs text-muted-foreground">
        No matching section. Try a CVE id, a feed name, or a control.
      </p>
    );
  }
  return (
    <div className="flex flex-col gap-1">
      {hits.map((h, i) => (
        <button
          key={`${h.slug}-${h.sectionId ?? "doc"}-${i}`}
          type="button"
          onClick={() => onPick(h.slug, h.sectionId ?? undefined)}
          className="rounded-md border border-border bg-card p-2.5 text-left transition-colors hover:border-primary/40"
        >
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-wide text-muted-foreground">
              {h.navLabel}
            </span>
            {h.sectionTitle && (
              <span className="truncate text-xs font-medium text-foreground">
                {h.sectionTitle}
              </span>
            )}
          </div>
          <p className="mt-1 line-clamp-2 text-[11px] leading-snug text-muted-foreground">
            {h.snippet}
          </p>
        </button>
      ))}
    </div>
  );
}
