"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { AuthShell, Field, FormError, SubmitButton } from "@/components/form";
import { api, ApiError } from "@/lib/api";

interface LoginResult {
  /** The gateway answers a correct password with this instead of a session
   *  when the account has a second factor enrolled. */
  mfa_required?: boolean;
}

export default function LoginPage() {
  const router = useRouter();
  // No pre-filled demo account: the v2 gateway seeds no users, so the old
  // analyst@logmonitor.dev / logmonitor123 pair would just fail.
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [needsCode, setNeedsCode] = useState(false);
  const [code, setCode] = useState("");

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api<LoginResult>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });

      // The password was right but the session is not issued yet. The cookie
      // we now hold authorises the code exchange and nothing else.
      if (result?.mfa_required) {
        setNeedsCode(true);
        setBusy(false);
        return;
      }
      router.push("/dashboard");
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Sign in failed");
      setBusy(false);
    }
  }

  async function onVerify(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/api/auth/mfa/verify", {
        method: "POST",
        body: JSON.stringify({ code: code.trim() }),
      });
      router.push("/dashboard");
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Verification failed");
      setBusy(false);
    }
  }

  if (needsCode) {
    return (
      <AuthShell title="Two-factor authentication" subtitle="SOC log analysis">
        <form onSubmit={onVerify} className="space-y-4">
          <Field
            id="code"
            label="Authentication code"
            value={code}
            onChange={setCode}
            autoComplete="one-time-code"
            placeholder="123456"
            hint="From your authenticator app, or use a recovery code."
          />
          <FormError message={error} />
          <SubmitButton busy={busy} busyLabel="Verifying…" disabled={code.trim() === ""}>
            Verify
          </SubmitButton>
          <p className="text-center text-xs text-slate-500">
            <button
              type="button"
              onClick={() => {
                setNeedsCode(false);
                setCode("");
                setError(null);
              }}
              className="text-sky-400 underline hover:text-sky-300"
            >
              Start over
            </button>
          </p>
        </form>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Sign in" subtitle="SOC log analysis">
      <form onSubmit={onSubmit} className="space-y-4">
        <Field
          id="email"
          label="Email"
          type="email"
          value={email}
          onChange={setEmail}
          autoComplete="email"
        />
        <Field
          id="password"
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
        />
        <FormError message={error} />
        <SubmitButton busy={busy} busyLabel="Signing in…">
          Sign in
        </SubmitButton>
        <p className="text-center text-xs text-slate-500">
          No account yet?{" "}
          <Link href="/register" className="text-sky-400 underline hover:text-sky-300">
            Create an organization
          </Link>
        </p>
      </form>
    </AuthShell>
  );
}
