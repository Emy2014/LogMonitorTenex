import { SeverityBadge, Card } from "@/components/ui";
import { SEVERITY_STYLES } from "@/lib/format";
import type { TimelineEvent } from "@/lib/types";

/** The brief's headline ask: a summarised timeline a SOC analyst can skim.
 *  Written by the LLM from the statistical evidence. */
export function Timeline({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) return null;

  return (
    <section>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">
        Timeline of events
      </h2>
      <Card className="p-5">
        <ol className="space-y-5">
          {events.map((e, i) => (
            <li key={i} className="relative flex gap-4">
              {/* connector line between markers */}
              {i < events.length - 1 && (
                <span
                  aria-hidden
                  className="absolute left-[5px] top-4 h-full w-px bg-slate-700"
                />
              )}
              <span
                aria-hidden
                className={`relative mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full border ${SEVERITY_STYLES[e.severity]}`}
              />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <time className="font-mono text-xs text-slate-500">{e.time_range}</time>
                  <SeverityBadge severity={e.severity} />
                </div>
                <p className="mt-1 font-medium">{e.headline}</p>
                <p className="mt-0.5 text-sm text-slate-400">{e.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      </Card>
    </section>
  );
}
