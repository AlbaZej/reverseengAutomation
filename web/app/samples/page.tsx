"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { listSamples, isLoggedIn } from "@/lib/api";
import { Search, Shield, ShieldAlert, ShieldCheck, ChevronLeft, ChevronRight } from "lucide-react";

const VERDICT_ICONS: Record<string, any> = {
  clean: ShieldCheck,
  suspicious: Shield,
  malicious: ShieldAlert,
};

const VERDICT_COLORS: Record<string, string> = {
  clean: "var(--accent-green)",
  suspicious: "var(--accent-yellow)",
  malicious: "var(--accent-red)",
};

export default function SamplesPage() {
  const router = useRouter();
  const [samples, setSamples] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [fileType, setFileType] = useState("");
  const [verdict, setVerdict] = useState("");
  const [loading, setLoading] = useState(true);

  const loadSamples = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listSamples({ page, search, file_type: fileType || undefined, verdict: verdict || undefined });
      setSamples(data.samples);
      setTotal(data.total);
    } catch {
      setSamples([]);
    } finally {
      setLoading(false);
    }
  }, [page, search, fileType, verdict]);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    loadSamples();
  }, [loadSamples, router]);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Sample History</h1>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)]" />
          <input
            type="text"
            placeholder="Search by filename, hash, or tag..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="w-full pl-10 pr-4 py-2 bg-[var(--bg-card)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[var(--accent-blue)] text-sm"
          />
        </div>
        <select
          value={fileType}
          onChange={(e) => { setFileType(e.target.value); setPage(1); }}
          className="px-3 py-2 bg-[var(--bg-card)] border border-[var(--border)] rounded-lg text-sm focus:outline-none"
        >
          <option value="">All types</option>
          <option value="pe">PE</option>
          <option value="elf">ELF</option>
          <option value="macho">Mach-O</option>
          <option value="pcap">PCAP</option>
          <option value="firmware">Firmware</option>
        </select>
        <select
          value={verdict}
          onChange={(e) => { setVerdict(e.target.value); setPage(1); }}
          className="px-3 py-2 bg-[var(--bg-card)] border border-[var(--border)] rounded-lg text-sm focus:outline-none"
        >
          <option value="">All verdicts</option>
          <option value="clean">Clean</option>
          <option value="suspicious">Suspicious</option>
          <option value="malicious">Malicious</option>
        </select>
      </div>

      {/* Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b border-[var(--border)]">
            <tr className="text-[var(--text-secondary)]">
              <th className="text-left px-4 py-3">File</th>
              <th className="text-left px-4 py-3">Type</th>
              <th className="text-left px-4 py-3">Verdict</th>
              <th className="text-left px-4 py-3">Findings</th>
              <th className="text-left px-4 py-3">Date</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={5} className="text-center py-8 text-[var(--text-secondary)]">
                  Loading...
                </td>
              </tr>
            ) : samples.length === 0 ? (
              <tr>
                <td colSpan={5} className="text-center py-8 text-[var(--text-secondary)]">
                  No samples found
                </td>
              </tr>
            ) : (
              samples.map((s) => {
                const v = s.analysis?.verdict;
                const VIcon = v ? VERDICT_ICONS[v] : null;
                const vColor = v ? VERDICT_COLORS[v] : "var(--text-secondary)";

                return (
                  <tr
                    key={s.id}
                    className="border-b border-[var(--border)]/50 hover:bg-[var(--bg-secondary)] cursor-pointer"
                    onClick={() => {
                      if (s.analysis?.job_id) router.push(`/analysis/${s.analysis.job_id}`);
                    }}
                  >
                    <td className="px-4 py-3">
                      <div className="font-medium">{s.filename}</div>
                      <div className="text-xs text-[var(--text-secondary)] font-mono">
                        {s.sha256?.slice(0, 16)}...
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs px-2 py-0.5 bg-[var(--bg-secondary)] rounded uppercase">
                        {s.file_type}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {VIcon && (
                        <div className="flex items-center gap-1.5" style={{ color: vColor }}>
                          <VIcon size={14} />
                          <span className="text-xs font-semibold uppercase">{v}</span>
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-[var(--text-secondary)]">
                      {s.analysis?.finding_count || 0}
                    </td>
                    <td className="px-4 py-3 text-[var(--text-secondary)] text-xs">
                      {new Date(s.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {total > 20 && (
        <div className="flex items-center justify-center gap-4">
          <button
            onClick={() => setPage(Math.max(1, page - 1))}
            disabled={page === 1}
            className="p-2 rounded-lg border border-[var(--border)] disabled:opacity-30"
          >
            <ChevronLeft size={16} />
          </button>
          <span className="text-sm text-[var(--text-secondary)]">
            Page {page} of {Math.ceil(total / 20)}
          </span>
          <button
            onClick={() => setPage(page + 1)}
            disabled={page >= Math.ceil(total / 20)}
            className="p-2 rounded-lg border border-[var(--border)] disabled:opacity-30"
          >
            <ChevronRight size={16} />
          </button>
        </div>
      )}
    </div>
  );
}
