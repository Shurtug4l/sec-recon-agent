// Typed access to the build-time docs corpus (scripts/gen-docs.mjs writes the
// JSON; see docs/frontend.md for the pipeline). The heavy work — markdown ->
// sanitized HTML, syntax highlighting, section extraction — happened at build
// time, so this module ships only data and small helpers to the client.

import generated from "./docs-generated.json";

export interface DocSection {
  id: string;
  title: string;
  depth: number;
  // Section prose, whitespace-collapsed; feeds client search only.
  content: string;
}

export interface Doc {
  slug: string;
  title: string;
  navLabel: string;
  purpose: string;
  html: string;
  sections: DocSection[];
  hasMermaid: boolean;
  githubUrl: string;
}

export interface DocGroup {
  name: string;
  docs: Doc[];
}

export const DOC_GROUPS: DocGroup[] = (generated as { groups: DocGroup[] }).groups;

export const DOCS: Doc[] = DOC_GROUPS.flatMap((g) => g.docs);

const BY_SLUG = new Map(DOCS.map((d) => [d.slug, d]));

export function getDoc(slug: string | null | undefined): Doc | undefined {
  return slug ? BY_SLUG.get(slug) : undefined;
}

export const DEFAULT_DOC_SLUG = DOCS[0]?.slug ?? "";
