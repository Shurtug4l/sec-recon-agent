// Client-side search over the docs corpus. Small and dependency-free: 11 docs
// with a few hundred sections total, so a linear scan with a simple relevance
// ordering beats pulling in a fuzzy-search library. Matches are substring,
// case-insensitive; ranking favors heading hits over body hits.

import { DOCS, type Doc } from "./docs";

export interface DocSearchHit {
  slug: string;
  docTitle: string;
  navLabel: string;
  sectionId: string | null;
  sectionTitle: string | null;
  // A short excerpt around the match, or the purpose for a doc-level hit.
  snippet: string;
  // Lower is more relevant (used for stable sort).
  rank: number;
}

function excerpt(text: string, at: number, len = 120): string {
  const start = Math.max(0, at - 40);
  const slice = text.slice(start, start + len);
  return (start > 0 ? "..." : "") + slice.trim() + (start + len < text.length ? "..." : "");
}

function searchDoc(doc: Doc, q: string): DocSearchHit[] {
  const hits: DocSearchHit[] = [];
  const titleHay = `${doc.navLabel} ${doc.title}`.toLowerCase();
  if (titleHay.includes(q)) {
    hits.push({
      slug: doc.slug,
      docTitle: doc.title,
      navLabel: doc.navLabel,
      sectionId: null,
      sectionTitle: null,
      snippet: doc.purpose,
      rank: 0,
    });
  }
  for (const sec of doc.sections) {
    const inTitle = sec.title.toLowerCase().includes(q);
    const bodyAt = sec.content.toLowerCase().indexOf(q);
    if (!inTitle && bodyAt < 0) continue;
    hits.push({
      slug: doc.slug,
      docTitle: doc.title,
      navLabel: doc.navLabel,
      sectionId: sec.id,
      sectionTitle: sec.title,
      snippet: inTitle ? excerpt(sec.content, 0) : excerpt(sec.content, bodyAt),
      // Heading matches (rank 1) rank above body-only matches (rank 2).
      rank: inTitle ? 1 : 2,
    });
  }
  return hits;
}

export function searchDocs(query: string, limit = 12): DocSearchHit[] {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  return DOCS.flatMap((d) => searchDoc(d, q))
    .sort((a, b) => a.rank - b.rank)
    .slice(0, limit);
}
