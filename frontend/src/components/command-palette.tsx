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

// Global Cmd+K / Ctrl+K palette. Provider-hoisted (next to TriageProvider in
// providers.tsx) so the keydown listener and the dialog exist on every route,
// and report-scoped commands can read the triage context.

interface CommandPaletteValue {
  openPalette: () => void;
}

const CommandPaletteContext = createContext<CommandPaletteValue | null>(null);

export function CommandPaletteProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const router = useRouter();
  const pathname = usePathname();
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

  const openPalette = useCallback(() => setOpen(true), []);
  const value = useMemo(() => ({ openPalette }), [openPalette]);

  return (
    <CommandPaletteContext.Provider value={value}>
      {children}
      <CommandDialog open={open} onOpenChange={setOpen}>
        <Command loop>
          <CommandInput placeholder="Type a command or search..." />
          <CommandList>
            <CommandEmpty>No matching commands.</CommandEmpty>
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
          </CommandList>
        </Command>
      </CommandDialog>
    </CommandPaletteContext.Provider>
  );
}

export function useCommandPalette(): CommandPaletteValue {
  const ctx = useContext(CommandPaletteContext);
  if (!ctx) {
    throw new Error("useCommandPalette must be used within a <CommandPaletteProvider>");
  }
  return ctx;
}
