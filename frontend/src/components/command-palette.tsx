"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { usePathname, useRouter } from "next/navigation";
import { defaultFilter, useCommandState } from "cmdk";
import { FileText } from "lucide-react";

import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from "@/components/ui/command";
import { useTriage } from "@/hooks/use-triage";
import { COMMANDS, GROUP_ORDER, type CommandCtx, type PaletteCommand } from "@/lib/commands";
import { DOCS_SELECT_EVENT } from "@/lib/nav-events";
import type { DocSearchHit } from "@/lib/docs-search";

// The docs corpus (docs-generated.json, ~650 KB) is code-split onto /docs.
// Pulling searchDocs in statically would drag it into every route's shared
// bundle, so the palette lazy-imports it the first time it opens and keeps the
// resolved function for the rest of the session. Doc hits stay empty until the
// chunk lands; commands work immediately.
type SearchDocsFn = (query: string, limit?: number) => DocSearchHit[];

// Doc hits are pre-filtered by searchDocs, so cmdk must not second-guess them:
// their value carries this sentinel and the palette's filter always keeps them
// (returning >0 also counts them toward filtered.count, so CommandEmpty still
// hides correctly). Commands keep cmdk's default fuzzy match untouched.
const DOC_HIT_PREFIX = "dochit:";

function paletteFilter(value: string, search: string, keywords?: string[]): number {
  if (value.startsWith(DOC_HIT_PREFIX)) return 1;
  return defaultFilter(value, search, keywords);
}

const DOC_HITS_LIMIT = 6;

// Global Cmd+K / Ctrl+K palette. Provider-hoisted (next to TriageProvider in
// providers.tsx) so the keydown listener and the dialog exist on every route,
// and report-scoped commands can read the triage context.

interface CommandPaletteValue {
  openPalette: () => void;
}

const CommandPaletteContext = createContext<CommandPaletteValue | null>(null);

export function CommandPaletteProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const [searchDocs, setSearchDocs] = useState<SearchDocsFn | null>(null);
  const router = useRouter();
  // Demo exports build with trailingSlash, so usePathname reports "/triage/";
  // normalize so the registry's exact-path checks hold in both build modes.
  const rawPathname = usePathname();
  const pathname = rawPathname !== "/" ? rawPathname.replace(/\/$/, "") : "/";
  const { state, entries, selectedId, run } = useTriage();

  useEffect(() => {
    // Platform-split on purpose: binding Ctrl+K on macOS too would hijack
    // the readline kill-line inside the triage textarea.
    const isMac = /Mac|iP(hone|ad|od)/.test(navigator.platform);
    const onKeyDown = (e: KeyboardEvent) => {
      const mod = isMac ? e.metaKey : e.ctrlKey;
      if (!mod || e.repeat || e.key.toLowerCase() !== "k") return;
      e.preventDefault();
      setOpen((o) => !o);
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  // Prefetch the docs-search chunk on first open so typing yields doc hits with
  // no async gap; the resolved function persists (provider never unmounts), so
  // the corpus loads at most once per session.
  useEffect(() => {
    if (!open || searchDocs) return;
    let cancelled = false;
    void import("@/lib/docs-search").then((m) => {
      if (!cancelled) setSearchDocs(() => m.searchDocs);
    });
    return () => {
      cancelled = true;
    };
  }, [open, searchDocs]);

  // Mirror the triage page's display logic: the report shown to the user is
  // the live run when the selected history entry IS the in-flight one,
  // otherwise the selected entry's persisted report.
  const selected = entries.find((e) => e.id === selectedId) ?? null;
  const isLiveSelection = state.currentEntryId !== null && state.currentEntryId === selectedId;
  const report = isLiveSelection ? state.report : (selected?.report ?? null);
  const query = selected?.query;

  const ctx = useMemo<CommandCtx>(
    () => ({ router, pathname, report, query, runTriage: run }),
    [router, pathname, report, query, run],
  );

  const execute = useCallback(
    (cmd: PaletteCommand) => {
      // Close first: letting radix restore focus before a navigation or a
      // print dialog avoids fighting the post-command focus target.
      setOpen(false);
      void cmd.run(ctx);
    },
    [ctx],
  );

  const runDocHit = useCallback(
    (hit: DocSearchHit) => {
      // Close first, same ordering as execute(): let radix restore focus
      // before the navigation retargets it.
      setOpen(false);
      const hash = hit.sectionId ? `#${hit.sectionId}` : "";
      if (pathname === "/docs") {
        // Already on /docs: rewrite the URL and let the page switch in place;
        // a router.push to the same route would not remount it.
        const url = new URL(window.location.href);
        url.searchParams.set("doc", hit.slug);
        url.hash = hit.sectionId ?? "";
        window.history.replaceState(null, "", url);
        window.dispatchEvent(new Event(DOCS_SELECT_EVENT));
      } else {
        router.push(`/docs?doc=${hit.slug}${hash}`);
      }
    },
    [pathname, router],
  );

  const openPalette = useCallback(() => setOpen(true), []);
  const value = useMemo(() => ({ openPalette }), [openPalette]);

  return (
    <CommandPaletteContext.Provider value={value}>
      {children}
      <CommandDialog open={open} onOpenChange={setOpen}>
        <Command loop filter={paletteFilter}>
          <CommandInput placeholder="Search docs, commands, pages..." />
          <CommandList>
            <CommandEmpty>No matching commands or docs.</CommandEmpty>
            {GROUP_ORDER.map((group) => {
              const items = COMMANDS.filter(
                (c) => c.group === group && (!c.visible || c.visible(ctx)),
              );
              if (items.length === 0) return null;
              return (
                <CommandGroup key={group} heading={group}>
                  {items.map((cmd) => (
                    <CommandItem
                      key={cmd.id}
                      // cmdk matches on value + keywords; the id suffix keeps
                      // values unique without polluting the visible label.
                      value={`${cmd.label} ${cmd.id}`}
                      keywords={cmd.keywords}
                      onSelect={() => execute(cmd)}
                    >
                      {cmd.icon ? <cmd.icon className="h-4 w-4 shrink-0 text-muted-foreground" /> : null}
                      <span className="truncate">{cmd.label}</span>
                      {cmd.hint ? <CommandShortcut>{cmd.hint}</CommandShortcut> : null}
                    </CommandItem>
                  ))}
                </CommandGroup>
              );
            })}
            <DocSearchResults searchDocs={searchDocs} onSelect={runDocHit} />
          </CommandList>
        </Command>
      </CommandDialog>
    </CommandPaletteContext.Provider>
  );
}

// Live global-search group. Rendered inside <Command> so it can read cmdk's
// own search state, keeping the input uncontrolled (single source of truth).
// Runs the lazy-loaded searchDocs over the corpus; nothing renders until the
// chunk resolves or the query is under two characters (searchDocs returns []).
function DocSearchResults({
  searchDocs,
  onSelect,
}: {
  searchDocs: SearchDocsFn | null;
  onSelect: (hit: DocSearchHit) => void;
}) {
  const search = useCommandState((s) => s.search);
  const hits = useMemo(
    () => (searchDocs ? searchDocs(search, DOC_HITS_LIMIT) : []),
    [searchDocs, search],
  );
  if (hits.length === 0) return null;
  return (
    <CommandGroup heading="Documentation">
      {hits.map((h) => (
        <CommandItem
          // Stable, unique per hit and prefixed so paletteFilter keeps it: the
          // snippet in the label changes per query, so an explicit value is
          // required (cmdk would otherwise infer it from the textContent).
          key={`${DOC_HIT_PREFIX}${h.slug}:${h.sectionId ?? "_doc"}`}
          value={`${DOC_HIT_PREFIX}${h.slug}:${h.sectionId ?? "_doc"}`}
          onSelect={() => onSelect(h)}
          className="items-start gap-2"
        >
          <FileText className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
          <span className="flex min-w-0 flex-col">
            <span className="flex items-center gap-2">
              <span className="font-mono text-[10px] uppercase tracking-wide text-muted-foreground">
                {h.navLabel}
              </span>
              {h.sectionTitle ? <span className="truncate">{h.sectionTitle}</span> : null}
            </span>
            <span className="line-clamp-1 text-xs text-muted-foreground">{h.snippet}</span>
          </span>
        </CommandItem>
      ))}
    </CommandGroup>
  );
}

export function useCommandPalette(): CommandPaletteValue {
  const ctx = useContext(CommandPaletteContext);
  if (!ctx) {
    throw new Error("useCommandPalette must be used within a <CommandPaletteProvider>");
  }
  return ctx;
}
