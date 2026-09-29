import { Card, ConfidenceBar, SeverityBadge } from "@/components/ui";
import { kindLabel } from "@/lib/format";
import type { Anomaly } from "@/lib/types";

/** Each anomaly shows *why* it was flagged and a confidence score -- both are
 *  explicit requirements of the bonus. */
export function AnomalyList({ anomalies }: { anomalies: Anomaly[] }) {
  if (anomalies.length === 0) {
    return (
      <Card className="p-6 text-center text-sm text-slate-400">
        No anomalies detected in this log.
      </Card>
    );
  }

  return (
    <div className="grid gap-3 md:grid-cols-2">
      {anomalies.map((a) => (
        <Card key={a.id} className="flex flex-col p-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                {kindLabel(a.kind)}
              </p>
            </div>
            <SeverityBadge severity={a.severity} />
          </div>

          <p className="mt-2 flex-1 text-sm leading-relaxed text-slate-300">
            {a.explanation}
          </p>

          {a.recommendation && (
            <p className="mt-3 border-l-2 border-slate-700 pl-3 text-sm text-slate-400">
              <span className="font-medium text-slate-300">Recommended: </span>
              {a.recommendation}
            </p>
          )}

          <div className="mt-4 flex items-center justify-between gap-3 border-t border-slate-800 pt-3">
            <ConfidenceBar value={a.confidence} />
            <span className="text-xs text-slate-500">
              {a.entry_ids.length.toLocaleString()} entr
              {a.entry_ids.length === 1 ? "y" : "ies"}
            </span>
          </div>
        </Card>
      ))}
    </div>
  );
}
