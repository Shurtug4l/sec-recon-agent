"use client";

import { memo, useEffect, useRef } from "react";

import { useTheme } from "@/hooks/use-theme";
import type { Doc } from "@/lib/docs";

// Renders one doc's build-time-generated HTML and, on the diagram-carrying
// docs, renders the mermaid blocks client-side. Mermaid is imported lazily and
// only when a `.docs-mermaid` block is actually present, so its weight is
// code-split onto this route and skipped entirely for the prose-only docs.
//
// memo is load-bearing, not an optimization: the mermaid SVGs are injected into
// the div imperatively (el.innerHTML), outside React's tree. The parent page
// re-renders on every scroll-spy tick, and an unmemoized re-render re-applies
// dangerouslySetInnerHTML with the original source, wiping the injected SVGs.
// The `doc` reference is stable while the slug holds, so memo skips those parent
// re-renders; a theme change still re-renders (useTheme is internal state).
export const DocContent = memo(function DocContent({ doc }: { doc: Doc }) {
  const ref = useRef<HTMLDivElement>(null);
  const { theme } = useTheme();

  useEffect(() => {
    if (!doc.hasMermaid) return;
    const root = ref.current;
    if (!root) return;
    const blocks = Array.from(root.querySelectorAll<HTMLDivElement>(".docs-mermaid"));
    if (blocks.length === 0) return;

    let cancelled = false;
    (async () => {
      const mermaid = (await import("mermaid")).default;
      if (cancelled) return;
      mermaid.initialize({
        startOnLoad: false,
        theme: theme === "light" ? "neutral" : "dark",
        // The SVG mermaid emits is DOMPurify-sanitized under 'strict'; matches
        // the security posture of rendering our own docs defensively anyway.
        securityLevel: "strict",
        fontFamily: "var(--font-mono), ui-monospace, monospace",
      });
      for (let i = 0; i < blocks.length; i++) {
        const el = blocks[i];
        // Stash the source once: after the first render el.innerHTML is the SVG,
        // so a theme re-render must re-parse from the preserved original.
        const src = el.dataset.mermaidSrc ?? el.textContent ?? "";
        el.dataset.mermaidSrc = src;
        try {
          const { svg } = await mermaid.render(`docs-mmd-${doc.slug}-${i}-${theme}`, src);
          if (cancelled) return;
          el.innerHTML = svg;
          el.dataset.rendered = "true";
        } catch {
          // Parse failure: leave the source text visible rather than a blank box.
          if (!cancelled && !el.dataset.rendered) el.dataset.mermaidError = "true";
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [doc.slug, doc.hasMermaid, theme]);

  return (
    <div
      ref={ref}
      className="docs-prose"
      // First-party content, sanitized at build time by the rehype-sanitize
      // allowlist in scripts/gen-docs.mjs. No runtime user input reaches this
      // string; the markdown source lives in the repo under docs/.
      dangerouslySetInnerHTML={{ __html: doc.html }}
    />
  );
});
