/** Shared form primitives for the auth pages.
 *
 *  Extracted when the register page arrived: two pages hand-rolling the same
 *  input markup would drift, and the focus ring is exactly the kind of detail
 *  that gets fixed in one copy and not the other.
 */

"use client";

interface FieldProps {
  id: string;
  label: string;
  type?: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete?: string;
  placeholder?: string;
  hint?: string;
  required?: boolean;
  /** Describes the field's own validation state to assistive tech. */
  invalid?: boolean;
}

export function Field({
  id,
  label,
  type = "text",
  value,
  onChange,
  autoComplete,
  placeholder,
  hint,
  required = true,
  invalid = false,
}: FieldProps) {
  const hintId = hint ? `${id}-hint` : undefined;

  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-sm text-slate-300">
        {label}
      </label>
      <input
        id={id}
        name={id}
        type={type}
        required={required}
        value={value}
        autoComplete={autoComplete}
        placeholder={placeholder}
        aria-invalid={invalid || undefined}
        aria-describedby={hintId}
        onChange={(e) => onChange(e.target.value)}
        className={`w-full rounded border bg-slate-950 px-3 py-2 text-sm outline-none transition-colors ${
          invalid
            ? "border-red-500/60 focus:border-red-400"
            : "border-slate-700 focus:border-sky-500"
        }`}
      />
      {hint && (
        <p id={hintId} className="mt-1.5 text-xs text-slate-500">
          {hint}
        </p>
      )}
    </div>
  );
}

export function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p
      role="alert"
      className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300"
    >
      {message}
    </p>
  );
}

export function SubmitButton({
  busy,
  children,
  busyLabel,
  disabled = false,
}: {
  busy: boolean;
  children: React.ReactNode;
  busyLabel: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="submit"
      disabled={busy || disabled}
      className="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-sky-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {busy ? busyLabel : children}
    </button>
  );
}

/** The card + heading both auth pages sit inside. */
export function AuthShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-semibold tracking-tight">LogMonitor</h1>
          <p className="mt-1 text-sm text-slate-400">{subtitle}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-6">
          <h2 className="mb-5 text-base font-medium">{title}</h2>
          {children}
        </div>
      </div>
    </main>
  );
}
