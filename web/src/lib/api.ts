/**
 * Thin fetch wrapper. Requests go to /api/* on this origin, which
 * next.config.ts rewrites to FastAPI -- so the session cookie is
 * first-party and no CORS setup is needed.
 */

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Read the double-submit CSRF token the gateway set.
 *
 * Deliberately NOT HttpOnly: the whole mechanism depends on same-origin script
 * being able to read it and echo it back in a header, which an attacker's page
 * cannot do across origins.
 */
function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)logmonitor_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : "";
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();

  const headers = new Headers(
    init?.body instanceof FormData ? init?.headers : { "Content-Type": "application/json", ...init?.headers },
  );
  if (!SAFE_METHODS.has(method)) {
    headers.set("X-CSRF-Token", csrfToken());
  }

  const res = await fetch(path, {
    ...init,
    credentials: "include",
    headers,
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* response had no JSON body */
    }
    throw new ApiError(res.status, detail);
  }

  return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
}
