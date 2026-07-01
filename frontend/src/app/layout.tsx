import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";

import { Providers } from "@/components/providers";
import "./globals.css";

// The type identity was declared in tailwind.config.ts but never loaded, so the
// app rendered in system-ui / Menlo. Load both via next/font (self-hosted at
// build, no layout shift) and expose them as CSS variables the Tailwind
// fontFamily tokens point at. JetBrains Mono is the deliberate signature on
// every telemetry token (CVE / CVSS / EPSS / ports / traceparent).
const inter = Inter({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "sec-recon-agent",
  description:
    "Type-safe security triage built on Pydantic AI and a custom MCP server. Portfolio project.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable}`}
      suppressHydrationWarning
    >
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
