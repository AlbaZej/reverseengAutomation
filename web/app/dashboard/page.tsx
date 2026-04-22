"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getDashboardStats, isLoggedIn } from "@/lib/api";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  FileSearch,
  BarChart3,
  Upload,
} from "lucide-react";

export default function DashboardPage() {
  const router = useRouter();
  const [stats, setStats] = useState<any>(null);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    getDashboardStats().then(setStats).catch(() => {});
  }, [router]);

  if (!stats) {
    return (
      <div className="flex items-center justify-center py-20 text-[var(--text-secondary)]">
        Loading dashboard...
      </div>
    );
  }

  const verdicts = stats.verdicts || {};
  const totalVerdicts = verdicts.clean + verdicts.suspicious + verdicts.malicious;

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <button
          onClick={() => router.push("/")}
          className="flex items-center gap-2 px-4 py-2 bg-[var(--accent-blue)] text-white rounded-lg text-sm font-semibold hover:opacity-90 transition"
        >
          <Upload size={16} /> Upload Sample
        </button>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard
          icon={<FileSearch size={24} />}
          label="Total Samples"
          value={stats.total_samples}
          color="var(--accent-blue)"
        />
        <StatCard
          icon={<BarChart3 size={24} />}
          label="Analyses Run"
          value={stats.total_analyses}
          color="var(--accent-purple)"
        />
        <StatCard
          icon={<ShieldAlert size={24} />}
          label="Malicious"
          value={verdicts.malicious || 0}
          color="var(--accent-red)"
        />
        <StatCard
          icon={<ShieldCheck size={24} />}
          label="Clean"
          value={verdicts.clean || 0}
          color="var(--accent-green)"
        />
      </div>

      {/* Verdict breakdown */}
      {totalVerdicts > 0 && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
          <h2 className="text-sm font-semibold text-[var(--text-secondary)] mb-4">
            Verdict Distribution
          </h2>
          <div className="flex h-4 rounded-full overflow-hidden bg-[var(--bg-secondary)]">
            {verdicts.malicious > 0 && (
              <div
                className="bg-[var(--accent-red)]"
                style={{ width: `${(verdicts.malicious / totalVerdicts) * 100}%` }}
              />
            )}
            {verdicts.suspicious > 0 && (
              <div
                className="bg-[var(--accent-yellow)]"
                style={{ width: `${(verdicts.suspicious / totalVerdicts) * 100}%` }}
              />
            )}
            {verdicts.clean > 0 && (
              <div
                className="bg-[var(--accent-green)]"
                style={{ width: `${(verdicts.clean / totalVerdicts) * 100}%` }}
              />
            )}
          </div>
          <div className="flex gap-6 mt-3 text-xs text-[var(--text-secondary)]">
            <span className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-[var(--accent-red)]" />
              Malicious ({verdicts.malicious})
            </span>
            <span className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-[var(--accent-yellow)]" />
              Suspicious ({verdicts.suspicious})
            </span>
            <span className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-[var(--accent-green)]" />
              Clean ({verdicts.clean})
            </span>
          </div>
        </div>
      )}

      {/* File type breakdown */}
      {Object.keys(stats.file_types || {}).length > 0 && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
          <h2 className="text-sm font-semibold text-[var(--text-secondary)] mb-4">
            File Types Analyzed
          </h2>
          <div className="flex gap-4 flex-wrap">
            {Object.entries(stats.file_types).map(([type, count]) => (
              <div
                key={type}
                className="px-4 py-2 bg-[var(--bg-secondary)] rounded-lg text-sm"
              >
                <span className="text-[var(--accent-blue)] font-semibold uppercase">
                  {type}
                </span>{" "}
                <span className="text-[var(--text-secondary)]">
                  ({count as number})
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Quick links */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <a
          href="/samples"
          className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 hover:border-[var(--accent-blue)] transition"
        >
          <h3 className="font-semibold mb-1">Sample History</h3>
          <p className="text-sm text-[var(--text-secondary)]">
            Search and browse all your uploaded samples
          </p>
        </a>
        <a
          href="/settings"
          className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 hover:border-[var(--accent-blue)] transition"
        >
          <h3 className="font-semibold mb-1">Settings</h3>
          <p className="text-sm text-[var(--text-secondary)]">
            API keys, integrations, and preferences
          </p>
        </a>
      </div>
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
      <div className="flex items-center gap-3">
        <div style={{ color }}>{icon}</div>
        <div>
          <div className="text-2xl font-bold">{value}</div>
          <div className="text-xs text-[var(--text-secondary)]">{label}</div>
        </div>
      </div>
    </div>
  );
}
