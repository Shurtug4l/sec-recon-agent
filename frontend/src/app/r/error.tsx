"use client";

import Link from "next/link";
import { ArrowRight, TriangleAlert } from "lucide-react";

import { Header } from "@/components/header";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

// Backstop for a link the decoder accepted and the view still cannot render: a
// validator cannot prove the view total, and the link's author picks the input.
// Anything thrown here would otherwise replace the app with Next's error screen.
export default function SharedReportError() {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main id="main-content" tabIndex={-1} className="container max-w-3xl flex-1 py-8 focus-visible:outline-none">
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center gap-3 py-14 text-center">
            <TriangleAlert className="h-6 w-6 text-warning" />
            <div>
              <p className="text-sm font-medium">Could not read this shared report</p>
              <p className="mt-1 text-xs text-muted-foreground">
                The link may be truncated or corrupted.
              </p>
            </div>
            <Button asChild size="sm">
              <Link href="/triage">
                Run a triage <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
