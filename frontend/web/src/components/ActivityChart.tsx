"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Card } from "@/components/ui";
import type { TimelineBucket } from "@/lib/types";

/** Requests over time. Buckets are aggregated in SQL, so this renders a few
 *  hundred points rather than every row in the file. */
export function ActivityChart({ buckets }: { buckets: TimelineBucket[] }) {
  if (buckets.length === 0) return null;

  const data = buckets.map((b) => ({
    time: new Date(b.bucket).toISOString().slice(11, 16),
    requests: b.total,
  }));

  return (
    <section>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">
        Requests over time
      </h2>
      <Card className="p-4">
        <div className="w-full max-w-full" style={{ aspectRatio: "16 / 9", minHeight: 200 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 8, bottom: 4, left: -16 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="time"
                tick={{ fill: "#64748b", fontSize: 11 }}
                stroke="#334155"
                interval="preserveStartEnd"
                minTickGap={28}
              />
              <YAxis
                tick={{ fill: "#64748b", fontSize: 11 }}
                stroke="#334155"
                allowDecimals={false}
              />
              <Tooltip
                cursor={{ fill: "#1e293b80" }}
                contentStyle={{
                  background: "#0f172a",
                  border: "1px solid #1e293b",
                  borderRadius: 6,
                  fontSize: 12,
                }}
                labelStyle={{ color: "#94a3b8" }}
              />
              <Bar dataKey="requests" fill="#0284c7" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>
    </section>
  );
}
