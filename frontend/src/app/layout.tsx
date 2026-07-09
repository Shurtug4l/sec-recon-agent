import type { Metadata } from "next";
import { Hanken_Grotesk, IBM_Plex_Mono, Martian_Mono } from "next/font/google";

import { Providers } from "@/components/providers";
import "./globals.css";

// Three-voice type system, all self-hosted via next/font (no request leaves
// the page, no layout shift). Hanken Grotesk carries body copy, IBM Plex Mono
// is the telemetry voice on every data token (CVE / CVSS / EPSS / ports /
// traceparent), Martian Mono is the display voice on h1/h2 and verdicts
// (wide instrument face, short strings only - the h1/h2 rule lives in
// globals.css so pages inherit it without per-page edits).
const hankenGrotesk = Hanken_Grotesk({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});

const ibmPlexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-mono",
  display: "swap",
});

const martianMono = Martian_Mono({
  subsets: ["latin"],
  variable: "--font-display",
  display: "swap",
});

// Runs before the body renders so the first paint already has the right
// theme (no flash). Stored preference wins, then the OS preference; the
// no-JS fallback is the :root default (dark). Kept inline and minimal on
// purpose: a theme dependency (next-themes) buys nothing over this.
const THEME_INIT = `(function(){var t;try{t=localStorage.getItem("theme")}catch(e){}if(t!=="light"&&t!=="dark"){t=window.matchMedia&&window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"}document.documentElement.dataset.theme=t})()`;

export const metadata: Metadata = {
  title: "sec-recon-agent - security triage that cites its sources",
  description:
    "Type-safe LLM vulnerability triage: a Pydantic AI agent grounds every verdict in NVD, CISA KEV, EPSS and Exploit-DB via 10 typed MCP tools, with a deterministic SSVC priority and a tamper-evident audit trail. Portfolio project.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${hankenGrotesk.variable} ${ibmPlexMono.variable} ${martianMono.variable}`}
      suppressHydrationWarning
    >
      <body>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT }} />
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
