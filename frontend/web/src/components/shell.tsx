/** The app shell: navigation, identity, and the auth guard every page shared
 *  by copy-paste before this existed. */

"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createContext, useContext, useEffect, useState } from "react";

import { Spinner } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import type { Me } from "@/lib/types";

const MeContext = createContext<Me | null>(null);

/** The signed-in user. Safe to call in any component inside AppShell, which
 *  does not render children until it has one. */
export function useMe(): Me {
  const me = useContext(MeContext);
  if (!me) throw new Error("useMe must be used inside AppShell");
  return me;
}

const NAV = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/uploads", label: "Uploads" },
  { href: "/org", label: "Organization", adminOnly: true },
  { href: "/settings/security", label: "Security" },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [me, setMe] = useState<Me | null>(null);
  const [failed, setFailed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const user = await api<Me>("/api/auth/me");
        if (!cancelled) setMe(user);
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 401) router.replace("/login");
        else setFailed(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [router]);

  // Close the mobile drawer on navigation, or it stays open over the new page.
  useEffect(() => setMenuOpen(false), [pathname]);

  async function logout() {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } finally {
      router.replace("/login");
    }
  }

  if (failed) {
    return (
      <main className="flex min-h-screen items-center justify-center px-4">
        <p role="alert" className="text-sm text-red-300">
          Could not reach the server. Check that the gateway is running.
        </p>
      </main>
    );
  }
  if (!me) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <Spinner label="Loading…" />
      </main>
    );
  }

  const links = NAV.filter((n) => !n.adminOnly || me.role === "admin" || me.role === "owner");

  return (
    <MeContext.Provider value={me}>
      <div className="min-h-screen">
        <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
          <div className="mx-auto flex max-w-7xl items-center gap-4 px-4 py-3">
            <Link href="/dashboard" className="shrink-0 font-semibold tracking-tight">
              LogMonitor
            </Link>

            <nav className="hidden flex-1 items-center gap-1 md:flex">
              {links.map((n) => (
                <NavLink key={n.href} href={n.href} active={pathname.startsWith(n.href)}>
                  {n.label}
                </NavLink>
              ))}
            </nav>

            <div className="ml-auto hidden items-center gap-3 text-sm md:flex">
              <div className="text-right leading-tight">
                <p className="text-slate-300">{me.email}</p>
                <p className="text-xs text-slate-500">
                  {me.org_name ?? "—"} · {me.role}
                </p>
              </div>
              <button
                onClick={logout}
                className="rounded border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-slate-600 hover:text-white"
              >
                Sign out
              </button>
            </div>

            <button
              onClick={() => setMenuOpen((v) => !v)}
              aria-expanded={menuOpen}
              aria-controls="mobile-nav"
              aria-label="Toggle navigation"
              className="ml-auto rounded border border-slate-700 px-2.5 py-1.5 text-xs md:hidden"
            >
              {menuOpen ? "Close" : "Menu"}
            </button>
          </div>

          {menuOpen && (
            <nav id="mobile-nav" className="border-t border-slate-800 px-4 py-3 md:hidden">
              <div className="flex flex-col gap-1">
                {links.map((n) => (
                  <NavLink key={n.href} href={n.href} active={pathname.startsWith(n.href)}>
                    {n.label}
                  </NavLink>
                ))}
              </div>
              <div className="mt-3 flex items-center justify-between border-t border-slate-800 pt-3 text-sm">
                <div className="min-w-0 leading-tight">
                  <p className="truncate text-slate-300">{me.email}</p>
                  <p className="text-xs text-slate-500">
                    {me.org_name ?? "—"} · {me.role}
                  </p>
                </div>
                <button
                  onClick={logout}
                  className="shrink-0 rounded border border-slate-700 px-2.5 py-1 text-xs text-slate-300"
                >
                  Sign out
                </button>
              </div>
            </nav>
          )}
        </header>

        {me.org_require_mfa && !me.mfa_enabled && (
          <div className="border-b border-amber-500/30 bg-amber-500/10 px-4 py-2.5 text-center text-sm text-amber-200">
            Your organization requires two-factor authentication.{" "}
            <Link href="/settings/security" className="underline hover:text-amber-100">
              Set it up now
            </Link>
          </div>
        )}

        <div className="mx-auto max-w-7xl px-4 py-6">{children}</div>
      </div>
    </MeContext.Provider>
  );
}

function NavLink({
  href,
  active,
  children,
}: {
  href: string;
  active: boolean;
  children: React.ReactNode;
}) {
  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={`rounded px-3 py-1.5 text-sm transition-colors ${
        active ? "bg-slate-800 text-white" : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
      }`}
    >
      {children}
    </Link>
  );
}
