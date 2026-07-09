import { Header } from "@/components/header";
import { ScorecardBands } from "@/components/scorecard/scorecard-bands";
import { Badge } from "@/components/ui/badge";
import { provenance } from "@/lib/scorecard";

export const metadata = {
  title: "Scorecard - sec-recon-agent",
  description:
    "A single reproducible measurement of the agent across security posture, detection quality, retrieval, efficiency, and calibration.",
};

export default function ScorecardPage() {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Header />
      <main id="main-content" tabIndex={-1} className="container max-w-5xl flex-1 py-8 focus-visible:outline-none">
        {/* Title + provenance stamp */}
        <div className="mb-6">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold tracking-tight">Scorecard</h1>
            <Badge variant="secondary" className="font-mono text-[10px]">
              model {provenance.model}
            </Badge>
          </div>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">
            One reproducible measurement across security posture, detection quality,
            retrieval, efficiency, and reliability. Every number here is parsed from the
            eval / retrieval / red-team result JSONs a live{" "}
            <code className="font-mono text-xs">make scorecard</code> run produced. Nothing
            is hand-authored; the misses are shown next to the wins. Measured on{" "}
            <span className="font-mono text-foreground">sonnet</span>: the deployment
            default is haiku and scores are model-specific, so these numbers do not
            transfer to other models (<code className="font-mono text-xs">make eval-compare</code>{" "}
            runs the same suite against haiku, sonnet, and opus side by side).
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
            <span>
              Date <span className="font-mono text-foreground">{provenance.date}</span>
            </span>
            <span>
              Commit <span className="font-mono text-foreground">{provenance.commit}</span>
            </span>
            <span>
              Reproduce <code className="font-mono text-foreground">make scorecard</code>
            </span>
          </div>
        </div>

        <ScorecardBands />

        <p className="mt-8 text-[11px] text-muted-foreground">
          Token pricing: {provenance.pricing_note}. Source: {provenance.source}. The full
          SCORECARD.md (with the deterministic SSVC decision table and the one-command
          reproduce block) lives in the repository root.
        </p>
      </main>
    </div>
  );
}
