"use client";

import { useState } from "react";

import { AppShell, useMe } from "@/components/shell";
import { Field, FormError, SubmitButton } from "@/components/form";
import { Card, PanelHeading } from "@/components/ui";
import { api, ApiError } from "@/lib/api";

export default function SecurityPage() {
  return (
    <AppShell>
      <Security />
    </AppShell>
  );
}

interface EnrollResponse {
  provisioning_uri: string;
  secret: string;
}

type Stage = "idle" | "enrolling" | "done";

function Security() {
  const me = useMe();
  const [enabled, setEnabled] = useState(Boolean(me.mfa_enabled));
  const [stage, setStage] = useState<Stage>("idle");
  const [enroll, setEnroll] = useState<EnrollResponse | null>(null);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function begin() {
    setBusy(true);
    setError(null);
    try {
      const res = await api<EnrollResponse>("/api/auth/mfa/enroll", { method: "POST" });
      setEnroll(res);
      setStage("enrolling");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not start enrolment.");
    } finally {
      setBusy(false);
    }
  }

  async function activate(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ recovery_codes: string[] }>("/api/auth/mfa/activate", {
        method: "POST",
        body: JSON.stringify({ code: code.trim() }),
      });
      setRecovery(res.recovery_codes);
      setEnabled(true);
      setStage("done");
      setCode("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not activate.");
    } finally {
      setBusy(false);
    }
  }

  async function disable(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/api/auth/mfa/disable", {
        method: "POST",
        body: JSON.stringify({ code: code.trim() }),
      });
      setEnabled(false);
      setStage("idle");
      setEnroll(null);
      setCode("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not disable.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Security</h1>
        <p className="text-sm text-slate-400">{me.email}</p>
      </div>

      <section>
        <PanelHeading>
          Two-factor authentication
          <span />
        </PanelHeading>

        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium ${
                enabled
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                  : "border-slate-600 bg-slate-800/50 text-slate-400"
              }`}
            >
              {/* Status carries an icon and a label, never colour alone. */}
              <span aria-hidden>{enabled ? "●" : "○"}</span>
              {enabled ? "Enabled" : "Not enabled"}
            </span>
            {me.org_require_mfa && (
              <span className="text-xs text-amber-300">Required by your organization</span>
            )}
          </div>

          {stage === "idle" && !enabled && (
            <>
              <p className="text-sm text-slate-300">
                Protect your account with a code from an authenticator app, in addition to your
                password.
              </p>
              <p className="mt-1.5 text-xs text-slate-500">
                This account can read proxy logs, which contain colleagues&rsquo; browsing
                history. A password alone is a single point of failure for that.
              </p>
              <FormError message={error} />
              <button
                onClick={begin}
                disabled={busy}
                className="mt-4 rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
              >
                {busy ? "Starting…" : "Set up"}
              </button>
            </>
          )}

          {stage === "enrolling" && enroll && (
            <form onSubmit={activate} className="space-y-4">
              <ol className="space-y-3 text-sm text-slate-300">
                <li>
                  <span className="text-slate-500">1.</span> Add this key to your authenticator
                  app:
                  <code className="mt-1.5 block break-all rounded border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-sky-300">
                    {enroll.secret}
                  </code>
                  <a
                    href={enroll.provisioning_uri}
                    className="mt-1.5 inline-block text-xs text-sky-400 underline hover:text-sky-300"
                  >
                    Or open it in your app
                  </a>
                </li>
                <li>
                  <span className="text-slate-500">2.</span> Enter the six-digit code it shows.
                </li>
              </ol>
              <Field
                id="code"
                label="Code"
                value={code}
                onChange={setCode}
                autoComplete="one-time-code"
                placeholder="123456"
              />
              <FormError message={error} />
              <div className="flex gap-2">
                <SubmitButton busy={busy} busyLabel="Verifying…" disabled={code.trim() === ""}>
                  Turn on
                </SubmitButton>
                <button
                  type="button"
                  onClick={() => { setStage("idle"); setEnroll(null); setError(null); }}
                  className="rounded border border-slate-700 px-3 py-2 text-sm text-slate-300"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          {stage === "done" && recovery && (
            <div>
              <p className="text-sm text-emerald-300">Two-factor authentication is on.</p>
              <p className="mt-3 text-sm text-slate-300">
                Save these recovery codes. Each works once, and{" "}
                <strong className="text-slate-100">this is the only time they are shown</strong>.
              </p>
              <ul className="mt-3 grid grid-cols-1 gap-1.5 rounded border border-slate-700 bg-slate-950 p-3 font-mono text-xs sm:grid-cols-2">
                {recovery.map((c) => (
                  <li key={c} className="tabular-nums text-slate-200">{c}</li>
                ))}
              </ul>
              <button
                onClick={() => { void navigator.clipboard?.writeText(recovery.join("\n")); }}
                className="mt-3 rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-slate-600"
              >
                Copy all
              </button>
            </div>
          )}

          {enabled && stage !== "done" && (
            <form onSubmit={disable} className="space-y-3">
              <p className="text-sm text-slate-300">
                Turning this off needs a current code, so a stolen session cannot quietly remove
                it.
              </p>
              {me.org_require_mfa && (
                <p className="text-xs text-amber-300">
                  Your organization requires two-factor authentication, so it cannot be turned
                  off.
                </p>
              )}
              <Field id="disable-code" label="Current code" value={code} onChange={setCode}
                     autoComplete="one-time-code" placeholder="123456" />
              <FormError message={error} />
              <button
                type="submit"
                disabled={busy || code.trim() === "" || Boolean(me.org_require_mfa)}
                className="rounded border border-red-500/50 px-3 py-2 text-sm text-red-300 hover:bg-red-500/10 disabled:opacity-40"
              >
                {busy ? "Working…" : "Turn off"}
              </button>
            </form>
          )}
        </Card>
      </section>
    </div>
  );
}
