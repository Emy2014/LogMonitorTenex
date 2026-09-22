"use client";

import { useCallback, useEffect, useState } from "react";

import { AppShell, useMe } from "@/components/shell";
import { Field, FormError } from "@/components/form";
import { Card, EmptyState, PanelHeading, Spinner } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { formatTime } from "@/lib/format";
import type { AccessGrant, AccessLevel, AuditEntry, OrgUser, Role } from "@/lib/types";

const LEVELS: { value: AccessLevel; label: string; detail: string }[] = [
  { value: "summary", label: "Summary", detail: "Narrative, risk and findings" },
  { value: "dashboard", label: "Dashboard", detail: "Also charts and aggregates" },
  { value: "full", label: "Full", detail: "Also raw log lines" },
];

export default function OrgPage() {
  return (
    <AppShell>
      <Org />
    </AppShell>
  );
}

function Org() {
  const me = useMe();
  const [users, setUsers] = useState<OrgUser[] | null>(null);
  const [grants, setGrants] = useState<AccessGrant[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [u, g, a] = await Promise.all([
        api<OrgUser[]>("/api/org/users"),
        api<AccessGrant[]>("/api/grants"),
        api<AuditEntry[]>("/api/audit?limit=25"),
      ]);
      setUsers(u);
      setGrants(g);
      setAudit(a);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load the organization.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const emailOf = (id: string) => users?.find((u) => u.id === id)?.email ?? id.slice(0, 8);

  if (!users) {
    return <div className="flex justify-center py-20"><Spinner label="Loading…" /></div>;
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{me.org_name}</h1>
        <p className="text-sm text-slate-400">{users.length} member{users.length === 1 ? "" : "s"}</p>
      </div>

      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
          {error}
        </p>
      )}

      <Members users={users} me={me.id} onChange={load} />
      <Grants grants={grants} users={users} emailOf={emailOf} onChange={load} />
      <AuditLog entries={audit} />
    </div>
  );
}

function Members({
  users, me, onChange,
}: { users: OrgUser[]; me: string; onChange: () => Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/api/org/invite", {
        method: "POST",
        body: JSON.stringify({ email: email.trim(), password, role }),
      });
      setEmail(""); setPassword(""); setOpen(false);
      await onChange();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not add the member.");
    } finally {
      setBusy(false);
    }
  }

  async function resetMFA(id: string) {
    setError(null);
    try {
      await api(`/api/org/users/${id}/mfa/reset`, { method: "POST" });
      await onChange();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reset.");
    }
  }

  return (
    <section>
      <PanelHeading
        aside={
          <button onClick={() => setOpen((v) => !v)} className="text-xs text-sky-400 hover:text-sky-300">
            {open ? "Cancel" : "Add member"}
          </button>
        }
      >
        Members
      </PanelHeading>

      {open && (
        <Card className="mb-3 p-4">
          <form onSubmit={invite} className="space-y-3">
            <Field id="invite-email" label="Email" type="email" value={email} onChange={setEmail} />
            <Field id="invite-password" label="Initial password" type="password" value={password}
                   onChange={setPassword} autoComplete="new-password"
                   hint="At least 10 characters. There is no mail transport yet, so you share this directly." />
            <div>
              <label htmlFor="invite-role" className="mb-1.5 block text-sm text-slate-300">Role</label>
              <select id="invite-role" value={role} onChange={(e) => setRole(e.target.value as Role)}
                      className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
                <option value="member">Member — sees only their own uploads</option>
                <option value="admin">Admin — sees org-wide aggregates, can grant access</option>
              </select>
            </div>
            <FormError message={error} />
            <button type="submit" disabled={busy}
                    className="rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50">
              {busy ? "Adding…" : "Add member"}
            </button>
          </form>
        </Card>
      )}

      {/* Card stack on phones, table from md up. A table forced wider than the
          screen is a horizontal-scroll strip, which is not a mobile layout. */}
      <Card className="divide-y divide-slate-800">
        {users.map((u) => (
          <div key={u.id} className="flex flex-wrap items-center justify-between gap-3 p-4">
            <div className="min-w-0">
              <p className="truncate text-sm">{u.email}{u.id === me && <span className="ml-2 text-xs text-slate-500">you</span>}</p>
              <p className="mt-0.5 text-xs capitalize text-slate-500">{u.role}</p>
            </div>
            {u.id !== me && (
              <button onClick={() => void resetMFA(u.id)}
                      className="shrink-0 rounded border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-slate-600">
                Reset 2FA
              </button>
            )}
          </div>
        ))}
      </Card>
      <p className="mt-2 text-xs text-slate-500">
        You cannot reset your own second factor — that would be a self-service bypass rather than
        a recovery path. Ask another administrator.
      </p>
    </section>
  );
}

function Grants({
  grants, users, emailOf, onChange,
}: {
  grants: AccessGrant[];
  users: OrgUser[];
  emailOf: (id: string) => string;
  onChange: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [subject, setSubject] = useState("");
  const [level, setLevel] = useState<AccessLevel>("dashboard");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      // upload_id omitted => a standing organization-wide grant.
      await api("/api/grants", {
        method: "POST",
        body: JSON.stringify({ subject_user_id: subject, level }),
      });
      setOpen(false);
      await onChange();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the grant.");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    try {
      await api(`/api/grants/${id}`, { method: "DELETE" });
      await onChange();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not revoke.");
    }
  }

  return (
    <section>
      <PanelHeading
        aside={
          <button onClick={() => setOpen((v) => !v)} className="text-xs text-sky-400 hover:text-sky-300">
            {open ? "Cancel" : "Grant access"}
          </button>
        }
      >
        Access grants
      </PanelHeading>

      {open && (
        <Card className="mb-3 p-4">
          <form onSubmit={create} className="space-y-3">
            <div>
              <label htmlFor="subject" className="mb-1.5 block text-sm text-slate-300">Grant to</label>
              <select id="subject" value={subject} onChange={(e) => setSubject(e.target.value)} required
                      className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
                <option value="">Choose a member…</option>
                {users.map((u) => <option key={u.id} value={u.id}>{u.email}</option>)}
              </select>
            </div>
            <fieldset>
              <legend className="mb-1.5 text-sm text-slate-300">Level</legend>
              <div className="space-y-1.5">
                {LEVELS.map((l) => (
                  <label key={l.value} className="flex items-start gap-2 text-sm">
                    <input type="radio" name="level" checked={level === l.value}
                           onChange={() => setLevel(l.value)} className="mt-1 accent-sky-500" />
                    <span>
                      {l.label}
                      <span className="block text-xs text-slate-500">{l.detail}</span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
            <p className="text-xs text-slate-500">
              This is an organization-wide grant covering every upload. Sharing one file is done
              from that upload.
            </p>
            <FormError message={error} />
            <button type="submit" disabled={busy || !subject}
                    className="rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50">
              {busy ? "Granting…" : "Grant"}
            </button>
          </form>
        </Card>
      )}

      <Card className="divide-y divide-slate-800">
        {grants.length === 0 ? (
          <EmptyState title="No grants issued" hint="Members see only their own uploads until granted more." />
        ) : (
          grants.map((g) => (
            <div key={g.id} className="flex flex-wrap items-center justify-between gap-3 p-4">
              <div className="min-w-0">
                <p className="truncate text-sm">{emailOf(g.subject_user_id)}</p>
                <p className="mt-0.5 text-xs text-slate-500">
                  <span className="capitalize">{g.level}</span> ·{" "}
                  {g.upload_id ? "one upload" : "organization-wide"} ·{" "}
                  granted by {emailOf(g.granted_by)}
                  {g.expires_at && ` · expires ${formatTime(g.expires_at)}`}
                </p>
              </div>
              <button onClick={() => void revoke(g.id)}
                      className="shrink-0 rounded border border-red-500/40 px-2.5 py-1 text-xs text-red-300 hover:bg-red-500/10">
                Revoke
              </button>
            </div>
          ))
        )}
      </Card>
    </section>
  );
}

function AuditLog({ entries }: { entries: AuditEntry[] }) {
  return (
    <section>
      <PanelHeading>Audit log</PanelHeading>
      <Card>
        {entries.length === 0 ? (
          <EmptyState title="Nothing recorded yet" />
        ) : (
          <ul className="divide-y divide-slate-800">
            {entries.map((e) => (
              <li key={e.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 p-3 text-sm">
                <code className={`rounded px-1.5 py-0.5 text-xs ${
                  e.action.startsWith("breakglass")
                    ? "bg-red-500/15 text-red-300"
                    : "bg-slate-800 text-slate-300"
                }`}>
                  {e.action}
                </code>
                <span className="text-slate-400">{e.actor_email ?? "—"}</span>
                <span className="ml-auto text-xs text-slate-500">{formatTime(e.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </section>
  );
}
