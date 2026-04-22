"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface EntropyRegion {
  offset: number;
  size: number;
  entropy: number;
  label: string;
}

const LABEL_COLORS: Record<string, string> = {
  empty: "#334155",
  normal: "#4a9eff",
  compressed: "#facc15",
  packed: "#f97316",
  encrypted: "#f87171",
};

export function EntropyChart({ regions }: { regions: EntropyRegion[] }) {
  const data = regions.map((r) => ({
    name: `0x${r.offset.toString(16)}`,
    entropy: r.entropy,
    label: r.label,
    size: r.size,
  }));

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data}>
          <XAxis
            dataKey="name"
            tick={{ fill: "#8888a0", fontSize: 10 }}
            interval="preserveStartEnd"
          />
          <YAxis
            domain={[0, 8]}
            tick={{ fill: "#8888a0", fontSize: 10 }}
            label={{
              value: "Entropy",
              angle: -90,
              position: "insideLeft",
              fill: "#8888a0",
              fontSize: 12,
            }}
          />
          <Tooltip
            contentStyle={{
              background: "#1a1a2e",
              border: "1px solid #2a2a3e",
              borderRadius: "8px",
              fontSize: "12px",
            }}
            formatter={(value: number, name: string, props: any) => [
              `${value.toFixed(4)} (${props.payload.label})`,
              "Entropy",
            ]}
          />
          <Bar dataKey="entropy">
            {data.map((entry, index) => (
              <Cell
                key={index}
                fill={LABEL_COLORS[entry.label] || LABEL_COLORS.normal}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <div className="flex gap-4 justify-center mt-3 text-xs">
        {Object.entries(LABEL_COLORS).map(([label, color]) => (
          <div key={label} className="flex items-center gap-1">
            <div
              className="w-3 h-3 rounded"
              style={{ backgroundColor: color }}
            />
            <span className="text-[var(--text-secondary)]">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
