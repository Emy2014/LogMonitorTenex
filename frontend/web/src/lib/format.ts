import type { Severity, Urgency } from "./types";

/** Tailwind classes per severity. Kept in one place so the colour language is
 *  consistent across badges, cards, the timeline and the chart. */
export const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-300 border-red-500/40",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  low: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  info: "bg-slate-500/15 text-slate-300 border-slate-500/40",
};

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function formatBytes(n: number | null): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}

export function formatTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toISOString().replace("T", " ").slice(0, 19);
}

/** Detector id -> a label an analyst would recognise. */
export const KIND_LABELS: Record<string, string> = {
  volume_spike: "Request burst",
  data_exfil: "Data exfiltration",
  beaconing: "C2 beaconing",
  blocked_threat: "Blocked threat",
  rare_destination: "Rare destination",
  off_hours: "Off-hours activity",
};

export function kindLabel(kind: string): string {
  return KIND_LABELS[kind] ?? kind.replace(/_/g, " ");
}

/** Urgency -> label. One vocabulary, so the findings matrix and the action
 *  plan cannot call the same urgency two different things on one page. */
export const URGENCY_LABEL: Record<Urgency, string> = {
  immediate: "Act now",
  today: "Today",
  this_week: "This week",
  monitor: "Monitor",
};
