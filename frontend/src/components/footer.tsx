import type { ElementType } from "react";
import Link from "next/link";
import { Mail, ShieldAlert } from "lucide-react";

import { GithubLogo } from "@/components/icons/github-logo";
import { LinkedinLogo } from "@/components/icons/linkedin-logo";

// Global site footer, mounted once in app/layout.tsx so it renders on every
// route (including /r). Pure server component: only links and CSS tokens, no
// state, so it adds nothing to the client bundle.

const REPO = "https://github.com/Shurtug4l/sec-recon-agent";

type FooterLink = { label: string; href: string; external?: boolean };

// Four link columns, mirroring the site taxonomy. Governance entries deep-link
// into the in-app docs (?doc=slug); Project entries point at the root files
// that are not yet surfaced in-app (README/SECURITY/CONTRIBUTING/LICENSE).
const COLUMNS: { heading: string; links: FooterLink[] }[] = [
  {
    heading: "Product",
    links: [
      { label: "Triage", href: "/triage" },
      { label: "Dashboard", href: "/dashboard" },
      { label: "Scorecard", href: "/scorecard" },
    ],
  },
  {
    heading: "Learn",
    links: [
      { label: "Guide", href: "/guide" },
      { label: "Case study", href: "/case-study" },
      { label: "Docs", href: "/docs" },
    ],
  },
  {
    heading: "Security & governance",
    links: [
      { label: "OWASP LLM Top 10", href: "/docs?doc=owasp_llm_top10" },
      { label: "MITRE ATLAS", href: "/docs?doc=mitre_atlas" },
      { label: "ISO/IEC 42001", href: "/docs?doc=iso_42001" },
      { label: "MCP self-audit", href: "/docs?doc=mcp_self_audit" },
    ],
  },
  {
    heading: "Project",
    links: [
      { label: "Source", href: REPO, external: true },
      { label: "Security policy", href: `${REPO}/blob/main/SECURITY.md`, external: true },
      { label: "Contributing", href: `${REPO}/blob/main/CONTRIBUTING.md`, external: true },
      { label: "License (MIT)", href: `${REPO}/blob/main/LICENSE`, external: true },
    ],
  },
];

// Contact / social links. The row grows automatically as entries are added.
const CONTACTS: { label: string; href: string; icon: ElementType; external?: boolean }[] = [
  { label: "GitHub repository", href: REPO, icon: GithubLogo, external: true },
  { label: "Email", href: "mailto:slaporta94@gmail.com", icon: Mail, external: true },
  {
    label: "LinkedIn",
    href: "https://www.linkedin.com/in/simonelaporta",
    icon: LinkedinLogo,
    external: true,
  },
];

const LINK_CLS =
  "text-sm text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:underline focus-visible:decoration-2";

const RING =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background";

function FooterLinkEl({ link }: { link: FooterLink }) {
  if (link.external) {
    return (
      <a href={link.href} target="_blank" rel="noopener noreferrer" className={LINK_CLS}>
        {link.label}
      </a>
    );
  }
  return (
    <Link href={link.href} className={LINK_CLS}>
      {link.label}
    </Link>
  );
}

export function Footer() {
  return (
    <footer className="border-t border-border bg-background">
      <div className="container py-12 md:py-14">
        <div className="grid gap-10 lg:grid-cols-12">
          {/* Brand + contacts. The mark is a PLACEHOLDER: swap the ShieldAlert
              icon below for the real <img>/<svg> logo once it exists. */}
          <div className="lg:col-span-4">
            <Link
              href="/"
              aria-label="sec-recon-agent home"
              className={`inline-flex items-center gap-2 rounded-md ${RING}`}
            >
              <span className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/10 text-primary">
                <ShieldAlert className="h-4 w-4" />
              </span>
              <span className="font-mono text-sm font-semibold">sec-recon-agent</span>
            </Link>
            <p className="mt-4 max-w-xs text-sm leading-relaxed text-muted-foreground">
              Type-safe, grounded, adversary-aware LLM vulnerability triage.
              Shipped like an architect, attacked like a security engineer.
            </p>
            <div className="mt-5 flex items-center gap-2">
              {CONTACTS.map((c) => {
                const Icon = c.icon;
                return (
                  <a
                    key={c.label}
                    href={c.href}
                    target={c.external ? "_blank" : undefined}
                    rel={c.external ? "noopener noreferrer" : undefined}
                    aria-label={c.label}
                    className={`inline-flex h-9 w-9 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground ${RING}`}
                  >
                    <Icon className="h-4 w-4" />
                  </a>
                );
              })}
            </div>
          </div>

          {/* Nav columns */}
          <nav
            aria-label="Footer"
            className="grid grid-cols-2 gap-8 sm:grid-cols-4 lg:col-span-8"
          >
            {COLUMNS.map((col) => (
              <div key={col.heading}>
                <h2 className="text-[11px] font-semibold uppercase tracking-widest text-foreground">
                  {col.heading}
                </h2>
                <ul className="mt-3 space-y-2">
                  {col.links.map((link) => (
                    <li key={link.label}>
                      <FooterLinkEl link={link} />
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
        </div>

        {/* Bottom bar */}
        <div className="mt-10 flex flex-col gap-3 border-t border-border pt-6 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-xs text-muted-foreground">
            &copy; 2026 Simone La Porta &middot; Released under the{" "}
            <a
              href={`${REPO}/blob/main/LICENSE`}
              target="_blank"
              rel="noopener noreferrer"
              className="underline underline-offset-2 hover:text-foreground"
            >
              MIT License
            </a>
            .
          </p>
          <p className="text-xs text-muted-foreground">
            A portfolio project. The live demo replays real captured triages, keyless.
          </p>
        </div>
      </div>
    </footer>
  );
}
