import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "sec-recon-agent",
  description:
    "Type-safe security triage built on Pydantic AI and a custom MCP server. Portfolio project.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>{children}</body>
    </html>
  );
}
