"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { ActivityChart } from "@/components/ActivityChart";
import { AnomalyList } from "@/components/AnomalyList";
import { EventsTable } from "@/components/EventsTable";
import { Timeline } from "@/components/Timeline";
import { Card, SeverityBadge, Spinner } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { SEVERITY_RANK } from "@/lib/format";
import type { Analysis, Severity, TimelineBucket } from "@/lib/types";

const POLL_MS = 1500;

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [buckets, setBuckets] = useState<TimelineBucket[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Analysis runs in a background task, so poll until it settles.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    let cancelled = false;

    async function poll() {
      try {
        const data = await api<Analysis>(`/api/analyses/${id}`);
        if (cancelled) return;
        setAnalysis(data);

        if (data.status === "done" || data.status === "failed") {
          if (data.status === "done") {
            setBuckets(await api<TimelineBucket[]>(`/api/analyses/${id}/timeline?minutes=15`));
          }
          return;
        }
        timer = setTimeout(poll, POLL_MS);
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 401) router.replace("/login");
        else setError("Could not load this analysis");
      }
    }

    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [id, router]);

  if (error) {
    return (
      <main className="mx-auto max-w-5xl p-6">
        <p className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
          {error}
        </p>
      </main>
    );
  }

  if (!analysis) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <Spinner label="Loading analysis…" />
      </main>
    );
  }

  if (analysis.status === "queued" || analysis.status === "running") {
    return (
      <main className="flex min-h-screen flex-col items-center justify-center gap-3">
        <Spinner label="Analyzing log…" />
        <p className="text-sm text-slate-500">
          Running detectors, then summarizing the findings.
        </p>
      </main>
    );
  }

  const counts = analysis.anomalies.reduce<Record<string, number>>((acc, a) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1;
    return acc;
  }, {});
  const severities = (Object.keys(counts) as Severity[]).sort(
    (a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b],
  );

  return (
    <main className="mx-auto max-w-5xl space-y-8 p-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link href="/dashboard" className="text-sm text-slate-400 hover:text-slate-200">
            ← Dashboard
          </Link>
          <h1 className="mt-1 text-xl font-semibold tracking-tight">Analysis</h1>
        </div>
        {analysis.overall_risk && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-slate-400">Overall risk</span>
            <SeverityBadge severity={analysis.overall_risk} />
          </div>
        )}
      </header>

      {analysis.status === "failed" && (
        <Card className="border-red-500/40 bg-red-500/10 p-4">
          <p className="font-medium text-red-300">Analysis failed</p>
          <p className="mt-1 font-mono text-xs text-red-200/80">{analysis.error}</p>
        </Card>
      )}

      {analysis.summary && (
        <Card className="p-5">
          <h2 className="mb-2 text-sm font-medium uppercase tracking-wide text-slate-400">
            Summary
          </h2>
          <p className="leading-relaxed text-slate-200">{analysis.summary}</p>

          <div className="mt-4 flex flex-wrap gap-4 border-t border-slate-800 pt-3 text-xs text-slate-500">
            <span>{analysis.anomalies.length} anomalies</span>
            {severities.map((s) => (
              <span key={s}>
                {counts[s]} {s}
              </span>
            ))}
            {analysis.model && <span>model: {analysis.model}</span>}
            {analysis.input_tokens != null && (
              <span>
                tokens: {analysis.input_tokens.toLocaleString()} in /{" "}
                {analysis.output_tokens?.toLocaleString()} out
              </span>
            )}
          </div>

          {/* The AI layer is optional -- statistical findings stand alone. */}
          {analysis.error === "no_api_key" && (
            <p className="mt-3 rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
              No <code>ANTHROPIC_API_KEY</code> configured, so the AI narrative and
              timeline are unavailable. Statistical detection and confidence scores
              below are unaffected.
            </p>
          )}
        </Card>
      )}

      {analysis.timeline && analysis.timeline.length > 0 && (
        <Timeline events={analysis.timeline} />
      )}

      <section>
        <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">
          Anomalies
        </h2>
        <AnomalyList anomalies={analysis.anomalies} />
      </section>

      <ActivityChart buckets={buckets} />

      <EventsTable analysisId={analysis.id} />
    </main>
  );
}
