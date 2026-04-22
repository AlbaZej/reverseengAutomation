"use client";

interface Finding {
  title: string;
  description: string;
  severity: string;
  source_tool: string;
  evidence: string;
  mitre_ids: string[];
}

const SEVERITY_COLORS: Record<string, string> = {
  info: "var(--accent-blue)",
  low: "var(--accent-green)",
  medium: "var(--accent-yellow)",
  high: "var(--accent-red)",
  critical: "#dc2626",
};

export function FindingsTable({ findings }: { findings: Finding[] }) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
      <table className="w-full text-sm">
        <thead className="border-b border-[var(--border)]">
          <tr className="text-[var(--text-secondary)]">
            <th className="text-left px-4 py-2 w-24">Severity</th>
            <th className="text-left px-4 py-2">Finding</th>
            <th className="text-left px-4 py-2 w-28">Source</th>
            <th className="text-left px-4 py-2 w-28">MITRE</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr
              key={i}
              className="border-b border-[var(--border)]/50 hover:bg-[var(--bg-secondary)]"
            >
              <td className="px-4 py-3">
                <span
                  className="px-2 py-0.5 rounded text-xs font-semibold uppercase"
                  style={{
                    color: SEVERITY_COLORS[f.severity] || "#fff",
                    backgroundColor: `${SEVERITY_COLORS[f.severity] || "#fff"}20`,
                  }}
                >
                  {f.severity}
                </span>
              </td>
              <td className="px-4 py-3">
                <div className="font-medium">{f.title}</div>
                <div className="text-[var(--text-secondary)] text-xs mt-0.5">
                  {f.description}
                </div>
              </td>
              <td className="px-4 py-3 text-[var(--text-secondary)]">
                {f.source_tool}
              </td>
              <td className="px-4 py-3">
                {f.mitre_ids.map((id) => (
                  <span
                    key={id}
                    className="text-xs text-[var(--accent-purple)] mr-1"
                  >
                    {id}
                  </span>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
