"use client";

import { useEffect, useState } from "react";

import { Card, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { formatBytes, formatTime } from "@/lib/format";
import type { EventPage } from "@/lib/types";

const PAGE_SIZE = 25;

/** Raw parsed entries, with anomalous rows highlighted.
 *
 *  Log content is rendered as text only -- a URL or user agent can contain
 *  markup, and React escapes by default. Nothing here uses
 *  dangerouslySetInnerHTML.
 */
export function EventsTable({ analysisId }: { analysisId: string }) {
  const [page, setPage] = useState<EventPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api<EventPage>(
      `/api/analyses/${analysisId}/events?limit=${PAGE_SIZE}&offset=${offset}&anomalous_only=${flaggedOnly}`,
    )
      .then((data) => !cancelled && setPage(data))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [analysisId, offset, flaggedOnly]);

  const flagged = new Set(page?.anomalous_entry_ids ?? []);
  const total = page?.total ?? 0;
  const lastOffset = Math.max(0, Math.floor((total - 1) / PAGE_SIZE) * PAGE_SIZE);

  return (
    <section>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
          Log entries
        </h2>
        <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-400">
          <input
            type="checkbox"
            checked={flaggedOnly}
            onChange={(e) => {
              setFlaggedOnly(e.target.checked);
              setOffset(0);
            }}
            className="accent-sky-500"
          />
          Anomalous only
        </label>
      </div>

      <Card>
        {/* Seven columns cannot be read at phone width. Below md the same
            rows render as cards; from md up, the table scrolls inside its own
            container so the page body never scrolls sideways. */}
        <ul className="divide-y divide-slate-800/70 md:hidden">
          {page?.items.map((row) => {
            const isFlagged = flagged.has(row.id);
            return (
              <li key={row.id} className={`p-3 ${isFlagged ? "bg-red-500/10" : ""}`}>
                <div className="flex items-baseline justify-between gap-2">
                  <span className="font-mono text-xs text-slate-400">
                    {isFlagged && (
                      <span className="mr-1.5 text-red-400" aria-label="Flagged as anomalous">●</span>
                    )}
                    {formatTime(row.ts)}
                  </span>
                  <span className={row.action === "Blocked" ? "text-xs text-red-300" : "text-xs text-slate-400"}>
                    {row.action ?? "—"}
                  </span>
                </div>
                <p className="mt-1 truncate text-sm" title={row.url ?? ""}>
                  {row.host ?? "—"}
                  {row.threat_name && (
                    <span className="ml-2 rounded bg-red-500/20 px-1.5 py-0.5 text-xs text-red-300">
                      {row.threat_name}
                    </span>
                  )}
                </p>
                <p className="mt-0.5 text-xs text-slate-500">
                  {row.username ?? "—"} · <span className="font-mono">{row.client_ip ?? "—"}</span>
                  {" · "}
                  {formatBytes(row.req_bytes ?? 0)} sent, {formatBytes(row.resp_bytes ?? 0)} received
                </p>
              </li>
            );
          })}
        </ul>

        <div className="hidden overflow-x-auto md:block">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-3 py-2 font-medium">Time</th>
                <th className="px-3 py-2 font-medium">User</th>
                <th className="px-3 py-2 font-medium">Source IP</th>
                <th className="px-3 py-2 font-medium">Host</th>
                <th className="px-3 py-2 font-medium">Action</th>
                <th className="px-3 py-2 text-right font-medium">Sent</th>
                <th className="px-3 py-2 text-right font-medium">Received</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {page?.items.map((row) => {
                const isFlagged = flagged.has(row.id);
                return (
                  <tr
                    key={row.id}
                    className={
                      isFlagged
                        ? "bg-red-500/10 hover:bg-red-500/15"
                        : "hover:bg-slate-800/40"
                    }
                  >
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-400">
                      {isFlagged && (
                        <span
                          className="mr-1.5 text-red-400"
                          title="Flagged as anomalous"
                          aria-label="Flagged as anomalous"
                        >
                          ●
                        </span>
                      )}
                      {formatTime(row.ts)}
                    </td>
                    <td className="px-3 py-2">{row.username ?? "—"}</td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">
                      {row.client_ip ?? "—"}
                    </td>
                    <td className="max-w-[260px] truncate px-3 py-2" title={row.url ?? ""}>
                      {row.host ?? "—"}
                      {row.threat_name && (
                        <span className="ml-2 rounded bg-red-500/20 px-1.5 py-0.5 text-xs text-red-300">
                          {row.threat_name}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={
                          row.action === "Blocked" ? "text-red-300" : "text-slate-400"
                        }
                      >
                        {row.action ?? "—"}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-right font-mono text-xs text-slate-400">
                      {formatBytes(row.req_bytes)}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-right font-mono text-xs text-slate-400">
                      {formatBytes(row.resp_bytes)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {loading && (
          <div className="flex justify-center p-4">
            <Spinner />
          </div>
        )}
        {!loading && page?.items.length === 0 && (
          <p className="p-6 text-center text-sm text-slate-500">No entries to show.</p>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 px-3 py-2 text-xs text-slate-500">
          <span>
            {total === 0
              ? "0 entries"
              : `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} of ${total.toLocaleString()}`}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              disabled={offset === 0}
              className="rounded border border-slate-700 px-2 py-1 hover:border-slate-500 disabled:opacity-40"
            >
              Previous
            </button>
            <button
              onClick={() => setOffset(Math.min(lastOffset, offset + PAGE_SIZE))}
              disabled={offset >= lastOffset}
              className="rounded border border-slate-700 px-2 py-1 hover:border-slate-500 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      </Card>
    </section>
  );
}
