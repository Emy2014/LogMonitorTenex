"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Legend, Line, LineChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";

import { ActionPlanPanel, StatusPanel } from "@/components/panels";
import { AppShell, useMe } from "@/components/shell";
import { Card, EmptyState, PanelHeading, Spinner, StatTile } from "@/components/ui";
import { api } from "@/lib/api";
import {
  AXIS, GRID, LATENCY, SEQUENTIAL, SERIES, TOOLTIP,
  formatBytes, formatCount, formatPercent,
} from "@/lib/chart";
import { URGENCY_LABEL } from "@/lib/format";
import type {
  ActionPlan, FindingCount, Severity, SeriesPoint, StatusBreakdown,
  SummaryResponse, TopRow, Urgency,
} from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const URGENCIES: Urgency[] = ["immediate", "today", "this_week", "monitor"];

// days: null means no lower bound.
//
// "All" is not a convenience here, it is usually the correct answer. Uploaded
// proxy logs are historical exports -- the bundled sample is dated March 2024
// -- so every bounded window shows an empty dashboard and the product looks
// broken.
const RANGES: { label: string; days: number | null }[] = [
  { label: "24h", days: 1 },
  { label: "7d", days: 7 },
  { label: "30d", days: 30 },
  { label: "90d", days: 90 },
  { label: "All", days: null },
];

const EPOCH = "1970-01-01T00:00:00Z";

export default function DashboardPage() {
  return (
    <AppShell>
      <Dashboard />
    </AppShell>
  );
}

function Dashboard() {
  const me = useMe();
  const isAdmin = me.role === "admin" || me.role === "owner";

  const [days, setDays] = useState<number | null>(30);
  // Set once, after the first response tells us where the data actually is.
  const [autoWidened, setAutoWidened] = useState(false);
  const [orgWide, setOrgWide] = useState(false);
  const [data, setData] = useState<SummaryResponse | null>(null);
  const [series, setSeries] = useState<SeriesPoint[]>([]);
  const [topHosts, setTopHosts] = useState<TopRow[]>([]);
  const [topUsers, setTopUsers] = useState<TopRow[]>([]);
  const [statuses, setStatuses] = useState<StatusBreakdown[]>([]);
  const [plan, setPlan] = useState<ActionPlan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const from = days === null ? EPOCH : new Date(Date.now() - days * 86_400_000).toISOString();
    const scope = orgWide && isAdmin ? "&scope=org" : "";
    const grain = days !== null && days <= 1 ? "minute" : "hour";
    try {
      const [summary, pts, hosts, users, status] = await Promise.all([
        api<SummaryResponse>(`/api/dashboard/summary?from=${from}${scope}`),
        api<{ points: SeriesPoint[] }>(`/api/dashboard/series?from=${from}&grain=${grain}${scope}`),
        api<{ rows: TopRow[] }>(`/api/dashboard/top?dimension=host&from=${from}${scope}`),
        api<{ rows: TopRow[] }>(`/api/dashboard/top?dimension=user&from=${from}${scope}`),
        api<{ codes: StatusBreakdown[] }>(`/api/dashboard/status?from=${from}${scope}`),
      ]);
      setData(summary);
      setSeries(pts.points);
      setTopHosts(hosts.rows);
      setTopUsers(users.rows);
      setStatuses(status.codes);

      // The window is empty but data exists outside it. Widen once rather than
      // showing a wall of empty charts over a log the user just uploaded.
      const s = summary.summary;
      if (!autoWidened && days !== null && s.requests === 0 && s.uploads > 0 && s.data_end) {
        setAutoWidened(true);
        setDays(null);
      }
    } catch {
      setError("Could not load the dashboard.");
    } finally {
      setLoading(false);
    }
  }, [days, orgWide, isAdmin, autoWidened]);

  useEffect(() => {
    void load();
  }, [load]);

  // The worklist is not windowed or scoped -- it is "what to do next", whole.
  // Loading it separately keeps a range toggle from refetching it unchanged.
  useEffect(() => {
    api<ActionPlan>(`/api/dashboard/actions?limit=15`).then(setPlan).catch(() => setPlan(null));
  }, []);

  if (loading && !data) {
    return (
      <div className="flex justify-center py-20">
        <Spinner label="Loading dashboard…" />
      </div>
    );
  }
  if (error || !data) {
    return (
      <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
        {error ?? "No data"}
      </p>
    );
  }

  const s = data.summary;
  // Nothing has ever been ingested. One honest message beats eleven panels
  // each saying "no data" in its own words.
  const neverIngested = s.empty && s.uploads === 0;

  const chartData = series.map((p) => ({
    t: new Date(p.bucket).toISOString().slice(5, 16).replace("T", " "),
    requests: p.requests,
    ok: p.requests - p.errors,
    errors: p.errors,
    bytesIn: p.bytes_in,
    bytesOut: p.bytes_out,
    p50: p.latency_p50_ms,
    p95: p.latency_p95_ms,
    p99: p.latency_p99_ms,
    cache: p.cache_total > 0 ? (p.cache_hits / p.cache_total) * 100 : null,
  }));


  return (
    <div className="space-y-6">
      {/* Filters sit in one row above the charts, not scattered per panel. */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-slate-400">
            {data.scope === "org" ? `All of ${me.org_name}` : "Your uploads"} ·{" "}
          {days === null ? "all history" : `last ${days}d`}
          {s.data_start && s.data_end && (
            <> · data spans {formatDay(s.data_start)} to {formatDay(s.data_end)}</>
          )}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {isAdmin && (
            <button
              onClick={() => setOrgWide((v) => !v)}
              className={`rounded border px-3 py-1.5 text-xs transition-colors ${
                orgWide
                  ? "border-sky-600 bg-sky-600/15 text-sky-300"
                  : "border-slate-700 text-slate-400 hover:text-slate-200"
              }`}
            >
              Organization-wide
            </button>
          )}
          <div className="flex overflow-hidden rounded border border-slate-700">
            {RANGES.map((r) => (
              <button
                key={r.label}
                onClick={() => { setAutoWidened(true); setDays(r.days); }}
                aria-pressed={days === r.days}
                className={`px-3 py-1.5 text-xs transition-colors ${
                  days === r.days ? "bg-slate-800 text-white" : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {!neverIngested && s.requests === 0 && s.uploads > 0 && days !== null && (
        <Card className="border-amber-900/50 bg-amber-950/20 p-4">
          <p className="text-sm text-slate-200">
            No activity in the last {days} days, but you have {s.uploads} upload
            {s.uploads === 1 ? "" : "s"}.
          </p>
          <p className="mt-1 text-xs text-slate-400">
            Uploaded logs are usually historical exports.{" "}
            {s.data_end && <>Yours ends {formatDay(s.data_end)}. </>}
            <button onClick={() => setDays(null)} className="text-sky-400 underline hover:text-sky-300">
              Show all history
            </button>
          </p>
        </Card>
      )}

      {neverIngested && (
        <Card className="border-sky-900/50 bg-sky-950/20 p-5">
          <p className="text-sm text-slate-200">No log data yet.</p>
          <p className="mt-1 max-w-2xl text-xs text-slate-400">
            Every panel below is wired to a live endpoint and will fill in on its own once
            ingestion is running. Upload handling is not built yet — it arrives with the
            streaming parser.
          </p>
        </Card>
      )}

      <section>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatTile label="Requests" value={formatCount(s.requests)} sub={`${s.hosts} hosts`} />
          <StatTile
            label="Success rate"
            value={formatPercent(s.success_rate)}
            sub={s.errors > 0 ? `${formatCount(s.errors)} failed` : "no failures"}
            tone={s.success_rate === null ? "default" : s.success_rate < 0.95 ? "bad" : "good"}
          />
          <StatTile
            label="p95 latency"
            value={s.latency_p95_ms === null ? "—" : `${s.latency_p95_ms} ms`}
            sub={s.latency_p50_ms === null ? undefined : `p50 ${s.latency_p50_ms} ms`}
          />
          <StatTile
            label="Cache hit rate"
            value={formatPercent(s.cache_hit_rate)}
            sub={s.cache_total > 0 ? `${formatCount(s.cache_total)} cacheable` : "not reported"}
          />
          <StatTile label="Received" value={formatBytes(s.bytes_in)} sub="inbound" />
          <StatTile label="Sent" value={formatBytes(s.bytes_out)} sub="outbound" />
          <StatTile label="Uploads" value={formatCount(s.uploads)} />
          <StatTile
            label="Action needed"
            value={formatCount(actionNeeded(data.findings))}
            tone={actionNeeded(data.findings) > 0 ? "warn" : "default"}
          />
        </div>
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Traffic over time">
          {chartData.length === 0 ? (
            <EmptyState title="No requests in this window" hint="Requests per bucket, from the rollup table." />
          ) : (
            <ChartBox>
              <BarChart data={chartData} margin={{ top: 4, right: 8, bottom: 4, left: -18 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={GRID} vertical={false} />
                <XAxis dataKey="t" tick={{ fill: AXIS, fontSize: 11 }} stroke={GRID} minTickGap={28} />
                <YAxis tick={{ fill: AXIS, fontSize: 11 }} stroke={GRID} allowDecimals={false} />
                <Tooltip cursor={{ fill: "#1e293b80" }} {...TOOLTIP} />
                <Bar dataKey="requests" name="Requests" fill={SERIES.requests} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ChartBox>
          )}
        </Panel>

        <Panel title="Successful vs failed">
          {chartData.length === 0 ? (
            <EmptyState title="No responses in this window" hint="Split on the log's own response code." />
          ) : (
            <ChartBox>
              <BarChart data={chartData} margin={{ top: 4, right: 8, bottom: 4, left: -18 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={GRID} vertical={false} />
                <XAxis dataKey="t" tick={{ fill: AXIS, fontSize: 11 }} stroke={GRID} minTickGap={28} />
                <YAxis tick={{ fill: AXIS, fontSize: 11 }} stroke={GRID} allowDecimals={false} />
                <Tooltip cursor={{ fill: "#1e293b80" }} {...TOOLTIP} />
                <Legend wrapperStyle={{ fontSize: 11, color: AXIS }} />
                {/* 2px gap between stacked segments, per the mark spec. */}
                <Bar dataKey="ok" name="2xx–3xx" stackId="s" fill={SERIES.requests} />
                <Bar dataKey="errors" name="4xx–5xx" stackId="s" fill={SERIES.errors} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ChartBox>
          )}
        </Panel>

        <Panel title="Latency percentiles">
          {chartData.length === 0 ? (
            <EmptyState
              title="No latency recorded"
              hint="Read from the log's own totalTime field, so it depends on that column being present."
            />
          ) : (
            <ChartBox>
              {/* One y-axis. p50/p95/p99 are ordered readings of one measure,
                  so they take a single-hue ramp rather than categorical hues. */}
              <LineChart data={chartData} margin={{ top: 4, right: 8, bottom: 4, left: -18 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={GRID} vertical={false} />
                <XAxis dataKey="t" tick={{ fill: AXIS, fontSize: 11 }} stroke={GRID} minTickGap={28} />
                <YAxis tick={{ fill: AXIS, fontSize: 11 }} stroke={GRID} unit=" ms" width={56} />
                <Tooltip {...TOOLTIP} />
                <Legend wrapperStyle={{ fontSize: 11, color: AXIS }} />
                <Line type="monotone" dataKey="p50" name="p50" stroke={LATENCY.p50} strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="p95" name="p95" stroke={LATENCY.p95} strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="p99" name="p99" stroke={LATENCY.p99} strokeWidth={2} dot={false} />
              </LineChart>
            </ChartBox>
          )}
        </Panel>

        <Panel title="Network usage">
          {chartData.length === 0 ? (
            <EmptyState title="No traffic measured" hint="Bytes in and out, summed per bucket." />
          ) : (
            <ChartBox>
              <AreaChart data={chartData} margin={{ top: 4, right: 8, bottom: 4, left: -18 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={GRID} vertical={false} />
                <XAxis dataKey="t" tick={{ fill: AXIS, fontSize: 11 }} stroke={GRID} minTickGap={28} />
                <YAxis tick={{ fill: AXIS, fontSize: 11 }} stroke={GRID} tickFormatter={formatBytes} width={64} />
                <Tooltip formatter={(v: number) => formatBytes(v)} {...TOOLTIP} />
                <Legend wrapperStyle={{ fontSize: 11, color: AXIS }} />
                <Area type="monotone" dataKey="bytesIn" name="Received" stroke={SERIES.bytesIn}
                      fill={SERIES.bytesIn} fillOpacity={0.18} strokeWidth={2} />
                <Area type="monotone" dataKey="bytesOut" name="Sent" stroke={SERIES.bytesOut}
                      fill={SERIES.bytesOut} fillOpacity={0.18} strokeWidth={2} />
              </AreaChart>
            </ChartBox>
          )}
        </Panel>
      </div>

      <Panel title="Response codes">
        <StatusPanel rows={statuses} />
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Top destinations">
          <TopTable rows={topHosts} emptyLabel="No hosts seen yet" />
        </Panel>
        <Panel title="Top users">
          <TopTable rows={topUsers} emptyLabel="No users seen yet" />
        </Panel>
      </div>

      {/* The worklist sits after the charts and immediately above Findings:
          the charts say what the traffic did, this says what to do about it,
          and Findings is the breakdown behind it. */}
      {plan && (
        <Panel title="Action plan">
          <ActionPlanPanel plan={plan} />
        </Panel>
      )}

      <Panel title="Findings">
        <FindingsMatrix findings={data.findings} />
      </Panel>
    </div>
  );
}

/** Just the date, for the "data spans X to Y" note. */
function formatDay(iso: string): string {
  return new Date(iso).toISOString().slice(0, 10);
}

function actionNeeded(findings: FindingCount[]): number {
  return findings
    .filter((f) => f.urgency === "immediate" || f.urgency === "today")
    .reduce((n, f) => n + f.count, 0);
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <PanelHeading>{title}</PanelHeading>
      <Card>{children}</Card>
    </section>
  );
}

/** aspect-ratio rather than a fixed height, so a chart is readable on a phone
 *  instead of being squeezed into a letterbox. */
function ChartBox({ children }: { children: React.ReactElement }) {
  return (
    <div className="w-full max-w-full p-3" style={{ aspectRatio: "16 / 9", minHeight: 200 }}>
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  );
}

function TopTable({ rows, emptyLabel }: { rows: TopRow[]; emptyLabel: string }) {
  if (rows.length === 0) return <EmptyState title={emptyLabel} />;
  const max = Math.max(...rows.map((r) => r.requests), 1);

  return (
    <ul className="divide-y divide-slate-800">
      {rows.map((r) => (
        <li key={r.label} className="flex items-center gap-3 px-4 py-2.5">
          <span className="min-w-0 flex-1 truncate text-sm" title={r.label}>
            {r.label}
          </span>
          <span className="hidden h-1.5 w-28 overflow-hidden rounded-full bg-slate-800 sm:block">
            <span
              className="block h-full rounded-full"
              style={{ width: `${(r.requests / max) * 100}%`, background: SERIES.requests }}
            />
          </span>
          <span className="w-16 shrink-0 text-right text-sm tabular-nums text-slate-300">
            {formatCount(r.requests)}
          </span>
          {r.errors > 0 && (
            <span className="w-14 shrink-0 text-right text-xs tabular-nums text-orange-300">
              {formatCount(r.errors)} err
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

/** Severity x urgency. Colour encodes the count (magnitude -> one hue), while
 *  the axes carry the two categories -- so the status palette is never asked
 *  to distinguish five severities by hue alone. */
function FindingsMatrix({ findings }: { findings: FindingCount[] }) {
  if (findings.length === 0) {
    return (
      <EmptyState
        title="No findings yet"
        hint="Detectors and the AI stage populate this once an analysis has run."
      />
    );
  }
  const max = Math.max(...findings.map((f) => f.count), 1);
  const at = (sev: Severity, urg: Urgency) =>
    findings.find((f) => f.severity === sev && f.urgency === urg)?.count ?? 0;

  return (
    <div className="overflow-x-auto p-4">
      <table className="w-full min-w-[420px] border-separate border-spacing-0.5 text-sm">
        <caption className="sr-only">Findings by severity and urgency</caption>
        <thead>
          <tr>
            <th scope="col" className="w-20 text-left text-xs font-normal text-slate-500" />
            {URGENCIES.map((u) => (
              <th key={u} scope="col" className="px-2 pb-2 text-xs font-normal text-slate-500">
                {URGENCY_LABEL[u]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {SEVERITIES.map((sev) => (
            <tr key={sev}>
              <th scope="row" className="pr-2 text-left text-xs font-normal capitalize text-slate-400">
                {sev}
              </th>
              {URGENCIES.map((u) => {
                const n = at(sev, u);
                const step = n === 0 ? null : SEQUENTIAL[Math.min(3, Math.floor((n / max) * 4))];
                return (
                  <td key={u} className="p-0">
                    <div
                      className="flex h-11 items-center justify-center rounded text-sm tabular-nums"
                      style={{
                        background: step ?? "#0f172a",
                        color: n === 0 ? "#475569" : "#f8fafc",
                      }}
                      title={`${sev} · ${URGENCY_LABEL[u]}: ${n}`}
                    >
                      {n || "·"}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
