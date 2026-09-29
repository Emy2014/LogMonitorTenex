/**
 * Chart tokens.
 *
 * Both palettes were checked with the dataviz validator against this app's
 * surface (#020617), not chosen by eye:
 *
 *   categorical  all 6 checks pass; worst adjacent CVD ΔE 10.1 (protan)
 *   sequential   monotone L, adjacent ΔL ≥ 0.06, single hue (5° spread)
 *
 * Tailwind's 400-level colors all sit around L 0.75, outside the dark-mode
 * band of 0.48–0.67, which is why these are 600-level rather than the
 * brighter shades the rest of the UI uses for text.
 */

/** Identity. Assigned in fixed order and never cycled — an entity keeps its
 *  hue when a filter changes how many series are on screen. */
export const CATEGORICAL = ["#0284c7", "#ea580c", "#059669", "#7c3aed"] as const;

/** Magnitude. One hue, light→dark, for heatmap cells and density. */
export const SEQUENTIAL = ["#0c4a6e", "#0369a1", "#0ea5e9", "#7dd3fc"] as const;

/** Named roles, so a chart reads by meaning rather than by index. */
export const SERIES = {
  requests: CATEGORICAL[0],
  errors: CATEGORICAL[1],
  bytesIn: CATEGORICAL[0],
  bytesOut: CATEGORICAL[2],
  cache: CATEGORICAL[2],
} as const;

/** Latency percentiles are ordered readings of one measure, so they take a
 *  single-hue ramp rather than categorical hues. */
export const LATENCY = {
  p50: SEQUENTIAL[3],
  p95: SEQUENTIAL[2],
  p99: SEQUENTIAL[1],
} as const;

export const AXIS = "#64748b";
export const GRID = "#1e293b";
export const SURFACE = "#020617";

/** Shared recharts tooltip styling — one definition so panels cannot drift. */
export const TOOLTIP = {
  contentStyle: {
    background: "#0f172a",
    border: "1px solid #1e293b",
    borderRadius: 6,
    fontSize: 12,
  },
  labelStyle: { color: "#94a3b8" },
} as const;

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function formatCount(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

export function formatPercent(v: number | null): string {
  return v === null ? "—" : `${(v * 100).toFixed(1)}%`;
}
