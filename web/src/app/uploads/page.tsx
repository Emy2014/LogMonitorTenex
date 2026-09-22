"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { AppShell } from "@/components/shell";
import { Card, EmptyState, SeverityBadge, Spinner } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { formatBytes, formatTime } from "@/lib/format";
import type { Upload, UploadResult } from "@/lib/types";

const MAX_BYTES = 512 * 1024 * 1024;
const ALLOWED = [".log", ".txt", ".csv", ".tsv"];

/** Still on its way to findings: the poll and the button must agree on this. */
const isAnalysing = (u: Upload) =>
  u.analysis_status === "queued" || u.analysis_status === "running";

export default function UploadsPage() {
  return (
    <AppShell>
      <Uploads />
    </AppShell>
  );
}

function Uploads() {
  const [uploads, setUploads] = useState<Upload[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [scope, setScope] = useState<"file" | "history">("file");
  const [windowDays, setWindowDays] = useState(30);
  const fileInput = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    try {
      setUploads(await api<Upload[]>("/api/uploads"));
    } catch {
      setError("Could not load uploads.");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Analysis runs in the workers, so while any upload is still being analysed
  // keep the list fresh; stop as soon as everything has settled.
  //
  // Chained rather than setInterval: a slow list query would otherwise stack
  // requests behind itself. The delay backs off because an analysis takes
  // seconds without an API key and about a minute with one, and a tab left
  // open on a stuck job should not poll every two seconds for ever.
  const pending = uploads?.some(isAnalysing) ?? false;
  useEffect(() => {
    if (!pending) return;
    let delay = 2000;
    let timer: ReturnType<typeof setTimeout>;
    let cancelled = false;

    const tick = async () => {
      if (!document.hidden) await load();
      if (cancelled) return;
      delay = Math.min(delay * 1.5, 15000);
      timer = setTimeout(tick, delay);
    };
    timer = setTimeout(tick, delay);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [pending, load]);

  // Re-run the analysis of an upload: one that predates automatic analysis,
  // or one to score against the scope currently selected above.
  async function analyse(upload: Upload) {
    setError(null);
    setBusy(`Queuing analysis of ${upload.filename}…`);
    try {
      await api(`/api/uploads/${upload.id}/analyze`, {
        method: "POST",
        body: JSON.stringify(
          scope === "history" ? { scope, baseline_window_days: windowDays } : { scope },
        ),
      });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not start the analysis.");
    } finally {
      setBusy(null);
    }
  }

  async function handleFile(file: File) {
    setError(null);
    if (!ALLOWED.some((ext) => file.name.toLowerCase().endsWith(ext))) {
      setError(`Unsupported file type. Expected: ${ALLOWED.join(", ")}`);
      return;
    }
    if (file.size > MAX_BYTES) {
      setError(`File is ${formatBytes(file.size)} — the limit is ${formatBytes(MAX_BYTES)}.`);
      return;
    }

    setBusy("Uploading…");
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("scope", scope);
      if (scope === "history") form.append("baseline_window_days", String(windowDays));
      const result = await api<UploadResult>("/api/uploads", { method: "POST", body: form });
      // The file is in either way; only the analysis can have failed to start,
      // and the row's Analyse button is the retry.
      if (!result.analysis) setError(result.analysis_error ?? "The analysis could not be started.");
      await load();
      setBusy(null);
    } catch (err) {
      // Ingest lands with the streaming parser; until then the gateway has no
      // route for this and says so plainly rather than hanging.
      setError(
        err instanceof ApiError && err.status === 404
          ? "Upload handling is not built yet — it arrives with the streaming parser."
          : err instanceof ApiError
            ? err.message
            : "Upload failed.",
      );
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Uploads</h1>
        <p className="text-sm text-slate-400">Drop a proxy log to analyse it.</p>
      </div>

      <Card className="p-4">
        <fieldset>
          <legend className="mb-2 text-xs uppercase tracking-wide text-slate-500">
            Analysis scope
          </legend>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-4">
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" name="scope" checked={scope === "file"}
                     onChange={() => setScope("file")} className="accent-sky-500" />
              This file only
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" name="scope" checked={scope === "history"}
                     onChange={() => setScope("history")} className="accent-sky-500" />
              Compare against history
            </label>
            {scope === "history" && (
              <select
                value={windowDays}
                onChange={(e) => setWindowDays(Number(e.target.value))}
                aria-label="Baseline window"
                className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm"
              >
                <option value={7}>last 7 days</option>
                <option value={30}>last 30 days</option>
                <option value={90}>last 90 days</option>
              </select>
            )}
          </div>
          <p className="mt-2 text-xs text-slate-500">
            {scope === "file"
              ? "Baselines come only from this file, so the same file always scores the same."
              : "Baselines come from your organization's aggregate history, which catches activity that looks ordinary inside one file."}
          </p>
        </fieldset>
      </Card>

      <section
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files?.[0];
          if (file) void handleFile(file);
        }}
        className={`rounded-lg border-2 border-dashed p-8 text-center transition-colors sm:p-10 ${
          dragging ? "border-sky-500 bg-sky-500/5" : "border-slate-700"
        }`}
      >
        {busy ? (
          <div className="flex justify-center"><Spinner label={busy} /></div>
        ) : (
          <>
            <p className="text-sm text-slate-300">
              Drop a proxy log here, or{" "}
              <button onClick={() => fileInput.current?.click()}
                      className="text-sky-400 underline hover:text-sky-300">
                browse
              </button>
            </p>
            <p className="mt-1.5 text-xs text-slate-500">
              {ALLOWED.join(", ")} — up to {formatBytes(MAX_BYTES)}
            </p>
            <input ref={fileInput} type="file" accept={ALLOWED.join(",")} className="hidden"
                   onChange={(e) => {
                     const file = e.target.files?.[0];
                     if (file) void handleFile(file);
                     e.target.value = "";
                   }} />
          </>
        )}
      </section>

      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
          {error}
        </p>
      )}

      <section>
        <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">
          Your uploads
        </h2>
        {uploads === null ? (
          <Card><EmptyState title="Loading…" /></Card>
        ) : uploads.length === 0 ? (
          <Card>
            <EmptyState
              title="Nothing uploaded yet"
              hint="Try samples/zscaler_suspicious.log from the repository."
            />
          </Card>
        ) : (
          <Card className="divide-y divide-slate-800">
            {uploads.map((u) => (
              <div key={u.id} className="flex flex-wrap items-center justify-between gap-3 p-4">
                <div className="min-w-0">
                  <p className="truncate font-medium">{u.filename}</p>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {u.parsed_count.toLocaleString()} of {u.line_count.toLocaleString()} lines ·{" "}
                    {formatBytes(u.byte_size)} · {formatTime(u.created_at)}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <AnalysisState upload={u} />
                  <button
                    onClick={() => void analyse(u)}
                    disabled={busy !== null || isAnalysing(u)}
                    className="rounded border border-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:border-sky-500 hover:text-sky-300 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {u.analysis_status ? "Re-analyse" : "Analyse"}
                  </button>
                </div>
              </div>
            ))}
          </Card>
        )}
      </section>
    </div>
  );
}

/** Where an upload is on its way to findings. Findings themselves live on the dashboard. */
function AnalysisState({ upload }: { upload: Upload }) {
  switch (upload.analysis_status) {
    case null:
      return <span className="text-xs text-slate-500">Not analysed</span>;
    case "queued":
    case "running":
      return (
        <span className="flex items-center gap-1.5 text-xs text-sky-300">
          <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-sky-400" />
          Analysing…
        </span>
      );
    case "failed":
      return <span className="text-xs text-red-300">Analysis failed</span>;
    case "done":
      return upload.overall_risk ? (
        <SeverityBadge severity={upload.overall_risk} />
      ) : (
        <span className="text-xs text-emerald-300">No findings</span>
      );
  }
}
