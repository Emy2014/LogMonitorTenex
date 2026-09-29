/** Two panels that answer questions a single number cannot: which failures,
 *  and what to do first. */

"use client";

import { EmptyState, SeverityBadge } from "@/components/ui";
import { formatCount } from "@/lib/chart";
import { URGENCY_LABEL, kindLabel } from "@/lib/format";
import type { ActionItem, ActionPlan, StatusBreakdown, Urgency } from "@/lib/types";

/** Status classes get their own colours from the semantic palette, kept
 *  separate from the categorical series colours so a status never
 *  impersonates a data series. Each ships with its label, never colour alone. */
const CLASS_STYLE: Record<StatusBreakdown["class"], { dot: string; text: string; label: string }> = {
  success:      { dot: "bg-emerald-500", text: "text-emerald-300", label: "OK" },
  redirect:     { dot: "bg-sky-500",     text: "text-sky-300",     label: "Redirect" },
  client_error: { dot: "bg-amber-500",   text: "text-amber-300",   label: "Client" },
  server_error: { dot: "bg-red-500",     text: "text-red-300",     label: "Server" },
};

/** Plain-English meaning, so a reader does not have to know the RFC. */
const CODE_MEANING: Record<number, string> = {
  200: "OK", 204: "No content", 301: "Moved", 302: "Found", 304: "Not modified",
  400: "Bad request", 401: "Authentication required", 403: "Forbidden",
  404: "Not found", 407: "Proxy auth required", 408: "Request timeout",
  429: "Rate limited", 500: "Server error", 502: "Bad gateway",
  503: "Unavailable", 504: "Gateway timeout",
};

export function StatusPanel({ rows }: { rows: StatusBreakdown[] }) {
  if (rows.length === 0) {
    return <EmptyState title="No responses recorded" hint="Read from the log's response code column." />;
  }
  // Failures first: the point of this panel is the ones that went wrong.
  const ordered = [...rows].sort((a, b) => {
    const rank = (r: StatusBreakdown) => (r.class === "server_error" ? 0 : r.class === "client_error" ? 1 : 2);
    return rank(a) - rank(b) || b.requests - a.requests;
  });
  const max = Math.max(...rows.map((r) => r.requests), 1);

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[520px] text-left text-sm">
        <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-4 py-2 font-medium">Code</th>
            <th className="px-3 py-2 font-medium">Meaning</th>
            <th className="px-3 py-2 font-medium">Reason given</th>
            <th className="px-3 py-2 text-right font-medium">Requests</th>
            <th className="px-3 py-2 text-right font-medium">p95</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/70">
          {ordered.map((r) => {
            const style = CLASS_STYLE[r.class];
            return (
              <tr key={r.code} className="hover:bg-slate-800/40">
                <td className="whitespace-nowrap px-4 py-2">
                  <span className="inline-flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full ${style.dot}`} aria-hidden />
                    <span className={`font-mono tabular-nums ${style.text}`}>{r.code}</span>
                    <span className="sr-only">{style.label}</span>
                  </span>
                </td>
                <td className="px-3 py-2 text-slate-300">{CODE_MEANING[r.code] ?? style.label}</td>
                <td className="max-w-[220px] truncate px-3 py-2 text-slate-500" title={r.reason ?? ""}>
                  {r.reason ?? "—"}
                </td>
                <td className="px-3 py-2 text-right">
                  <span className="inline-flex items-center justify-end gap-2">
                    <span className="hidden h-1.5 w-16 overflow-hidden rounded-full bg-slate-800 sm:block">
                      <span className={`block h-full ${style.dot}`} style={{ width: `${(r.requests / max) * 100}%` }} />
                    </span>
                    <span className="tabular-nums text-slate-300">{formatCount(r.requests)}</span>
                    <span className="w-12 text-xs tabular-nums text-slate-500">
                      {(r.share * 100).toFixed(1)}%
                    </span>
                  </span>
                </td>
                {/* A 502 after 30s is an upstream timeout; a 403 in 5ms is
                    policy. Latency beside the code separates them. */}
                <td className="px-3 py-2 text-right tabular-nums text-slate-400">
                  {r.latency_p95_ms === null ? "—" : `${r.latency_p95_ms} ms`}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Chip colours only; the labels come from format.ts so they match the rest
 *  of the app. */
const URGENCY_CHIP: Record<Urgency, string> = {
  immediate: "border-red-500/50 bg-red-500/10 text-red-300",
  today:     "border-amber-500/50 bg-amber-500/10 text-amber-300",
  this_week: "border-sky-500/50 bg-sky-500/10 text-sky-300",
  monitor:   "border-slate-600 bg-slate-800/50 text-slate-400",
};

// Summary chips, most urgent first. Counted from the items themselves rather
// than sent alongside them, so the header can never disagree with the list.
const SUMMARISED: Urgency[] = ["immediate", "today", "this_week"];

export function ActionPlanPanel({ plan }: { plan: ActionPlan }) {
  if (plan.items.length === 0) {
    return (
      <EmptyState
        title="Nothing outstanding"
        hint="Findings appear here ordered by what to do first, once an analysis has run."
      />
    );
  }
  const counts = SUMMARISED.map(
    (u) => [u, plan.items.filter((i) => i.urgency === u).length] as const,
  );
  const nothingToday = counts[0][1] === 0 && counts[1][1] === 0;

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 px-4 py-3 text-xs">
        {counts.map(([urgency, n]) =>
          n > 0 ? <UrgencyChip key={urgency} urgency={urgency} n={n} /> : null,
        )}
        {nothingToday && <span className="text-slate-500">Nothing needs attention today.</span>}
      </div>

      <ol className="divide-y divide-slate-800">
        {plan.items.map((item, i) => (
          <ActionRow key={item.anomaly_id} item={item} index={i + 1} />
        ))}
      </ol>
    </div>
  );
}

/** The urgency chip, with an optional leading count. */
function UrgencyChip({ urgency, n }: { urgency: Urgency; n?: number }) {
  const label = URGENCY_LABEL[urgency];
  return (
    <span className={`rounded border px-2 py-0.5 text-xs font-medium ${URGENCY_CHIP[urgency]}`}>
      {n === undefined ? label : `${n} ${label.toLowerCase()}`}
    </span>
  );
}

function ActionRow({ item, index }: { item: ActionItem; index: number }) {
  return (
    <li className="flex gap-3 p-4">
      {/* Numbered because this is a worklist in priority order, not a set of
          unrelated cards. The number encodes something true. */}
      <span className="mt-0.5 w-5 shrink-0 text-right font-mono text-xs text-slate-600">{index}</span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <UrgencyChip urgency={item.urgency} />
          <SeverityBadge severity={item.severity} />
          <span className="text-xs uppercase tracking-wide text-slate-500">
            {kindLabel(item.kind)}
          </span>
          <span className="text-xs text-slate-600">
            {Math.round(item.confidence * 100)}% confidence
          </span>
        </div>
        <p className="mt-1.5 text-sm text-slate-200">{item.explanation}</p>
        {item.recommendation && (
          <p className="mt-1 text-sm text-sky-300">→ {item.recommendation}</p>
        )}
        <p className="mt-1 text-xs text-slate-500">
          {formatCount(item.entries)} log {item.entries === 1 ? "line" : "lines"} · {item.filename}
        </p>
      </div>
    </li>
  );
}
