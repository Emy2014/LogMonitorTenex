"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { AuthShell, Field, FormError, SubmitButton } from "@/components/form";
import { api, ApiError } from "@/lib/api";
import type { User } from "@/lib/types";

/** Mirrors the server: gateway/internal/handlers/auth.go rejects anything
 *  shorter. Checked here too so the failure is immediate rather than a round
 *  trip, but the server is the one that actually enforces it. */
const MIN_PASSWORD = 10;

/** The server derives the org slug by lowercasing and stripping non-alphanumerics,
 *  then rejects an empty result. A name of only punctuation would 400, so catch
 *  it here where we can say why. */
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export default function RegisterPage() {
  const router = useRouter();
  const [orgName, setOrgName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const slug = slugify(orgName);
  const slugInvalid = orgName.trim() !== "" && slug === "";
  const passwordShort = password !== "" && password.length < MIN_PASSWORD;
  const mismatch = confirm !== "" && confirm !== password;

  const ready =
    orgName.trim() !== "" &&
    email.trim() !== "" &&
    password.length >= MIN_PASSWORD &&
    confirm === password &&
    !slugInvalid;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password !== confirm) {
      setError("The two passwords do not match.");
      return;
    }
    if (password.length < MIN_PASSWORD) {
      setError(`Password must be at least ${MIN_PASSWORD} characters.`);
      return;
    }

    setBusy(true);
    try {
      // Creates the organization and makes this user its owner. Joining an
      // existing organization is by admin invitation only -- otherwise anyone
      // who guessed a slug could enrol themselves as a tenant.
      await api<User>("/api/auth/register", {
        method: "POST",
        body: JSON.stringify({
          org_name: orgName.trim(),
          email: email.trim(),
          password,
        }),
      });
      router.push("/dashboard");
      router.refresh();
    } catch (err) {
      // The gateway returns 409 for both conflicts with distinct messages, so
      // surfacing its text is more useful than a generic failure.
      setError(
        err instanceof ApiError ? err.message : "Could not create the account.",
      );
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Create an organization" subtitle="SOC log analysis">
      <form onSubmit={onSubmit} className="space-y-4" noValidate>
        <Field
          id="org_name"
          label="Organization name"
          value={orgName}
          onChange={setOrgName}
          autoComplete="organization"
          placeholder="Acme Security"
          invalid={slugInvalid}
          hint={
            slugInvalid
              ? "Needs at least one letter or digit."
              : slug
                ? `Your workspace will be “${slug}”.`
                : "You will be its owner and can invite colleagues afterwards."
          }
        />

        <Field
          id="email"
          label="Work email"
          type="email"
          value={email}
          onChange={setEmail}
          autoComplete="email"
          placeholder="analyst@acme.io"
        />

        <Field
          id="password"
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="new-password"
          invalid={passwordShort}
          hint={
            passwordShort
              ? `${MIN_PASSWORD - password.length} more character${
                  MIN_PASSWORD - password.length === 1 ? "" : "s"
                } needed.`
              : `At least ${MIN_PASSWORD} characters.`
          }
        />

        <Field
          id="confirm"
          label="Confirm password"
          type="password"
          value={confirm}
          onChange={setConfirm}
          autoComplete="new-password"
          invalid={mismatch}
          hint={mismatch ? "These do not match." : undefined}
        />

        <FormError message={error} />

        <SubmitButton busy={busy} busyLabel="Creating…" disabled={!ready}>
          Create organization
        </SubmitButton>

        <p className="text-center text-xs text-slate-500">
          Already have an account?{" "}
          <Link href="/login" className="text-sky-400 underline hover:text-sky-300">
            Sign in
          </Link>
        </p>
      </form>
    </AuthShell>
  );
}
