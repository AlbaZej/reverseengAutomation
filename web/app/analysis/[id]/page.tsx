"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { getAnalysis, getExportUrl, addAnnotation, isLoggedIn } from "@/lib/api";
import { EntropyChart } from "@/components/EntropyChart";
import { FindingsTable } from "@/components/FindingsTable";
import { AiPanel } from "@/components/AiPanel";
import {
  Download,
  Loader2,
  MessageSquare,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
} from "lucide-react";

export default function AnalysisPage() {
  const params = useParams();
  const jobId = params.id as string;
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const poll = async () => {
      try {
        const result = await getAnalysis(jobId);
        setData(result);

        if (result.status === "pending" || result.status === "running") {
          setTimeout(poll, 2000);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load");
      }
    };
    poll();
  }, [jobId]);

  if (error) {
    return (
      <div className="text-center py-20">
        <AlertTriangle size={48} className="mx-auto text-[var(--accent-red)] mb-4" />
        <p className="text-[var(--accent-red)]">{error}</p>
      </div>
    );
  }

  if (!data || data.status === "pending" || data.status === "running") {
    return (
      <div className="flex flex-col items-center gap-4 py-20">
        <Loader2 size={48} className="animate-spin text-[var(--accent-blue)]" />
        <p className="text-[var(--text-secondary)]">
          {data?.status === "running"
            ? "Analysis in progress..."
            : "Waiting to start..."}
        </p>
      </div>
    );
  }

  if (data.status === "failed") {
    return (
      <div className="text-center py-20">
        <AlertTriangle size={48} className="mx-auto text-[var(--accent-red)] mb-4" />
        <p className="text-[var(--accent-red)]">Analysis failed: {data.error}</p>
      </div>
    );
  }

  const report = data.report;
  if (!report) return null;

  const VerdictIcon =
    report.verdict === "malicious"
      ? ShieldAlert
      : report.verdict === "suspicious"
        ? Shield
        : ShieldCheck;

  const verdictColor =
    report.verdict === "malicious"
      ? "var(--accent-red)"
      : report.verdict === "suspicious"
        ? "var(--accent-yellow)"
        : "var(--accent-green)";

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold mb-2">
            {report.file_info.path.split(/[/\\]/).pop()}
          </h1>
          <div className="flex gap-4 text-sm text-[var(--text-secondary)]">
            <span>{report.file_info.file_type.toUpperCase()}</span>
            <span>{report.file_info.architecture}</span>
            <span>{(report.file_info.size / 1024).toFixed(1)} KB</span>
          </div>
        </div>
        <div
          className="flex items-center gap-2 px-4 py-2 rounded-lg border"
          style={{ borderColor: verdictColor, color: verdictColor }}
        >
          <VerdictIcon size={20} />
          <span className="font-bold uppercase">{report.verdict}</span>
          <span className="text-xs opacity-70">
            {(report.verdict_confidence * 100).toFixed(0)}%
          </span>
        </div>
      </div>

      {/* Hashes */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <h2 className="text-sm font-semibold text-[var(--text-secondary)] mb-2">
          Hashes
        </h2>
        <div className="grid grid-cols-1 gap-1 text-sm font-mono">
          <div>
            <span className="text-[var(--text-secondary)]">MD5: </span>
            {report.file_info.md5}
          </div>
          <div>
            <span className="text-[var(--text-secondary)]">SHA256: </span>
            {report.file_info.sha256}
          </div>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard label="Findings" value={report.summary.findings_count} />
        <StatCard label="YARA Matches" value={report.summary.yara_matches} />
        <StatCard label="IOCs" value={report.summary.ioc_count} />
        <StatCard label="Strings" value={report.summary.total_strings} />
        <StatCard label="Functions" value={report.summary.function_count} />
      </div>

      {/* Findings */}
      {report.findings.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-4">Findings</h2>
          <FindingsTable findings={report.findings} />
        </div>
      )}

      {/* Entropy chart */}
      {report.entropy_regions.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-4">Entropy Map</h2>
          <EntropyChart regions={report.entropy_regions} />
        </div>
      )}

      {/* IOCs */}
      {report.iocs.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-4">
            Indicators of Compromise ({report.iocs.length})
          </h2>
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead className="border-b border-[var(--border)]">
                <tr className="text-[var(--text-secondary)]">
                  <th className="text-left px-4 py-2">Type</th>
                  <th className="text-left px-4 py-2">Value</th>
                  <th className="text-left px-4 py-2">Context</th>
                </tr>
              </thead>
              <tbody>
                {report.iocs.map((ioc: any, i: number) => (
                  <tr key={i} className="border-b border-[var(--border)]/50">
                    <td className="px-4 py-2 text-[var(--accent-purple)]">
                      {ioc.type}
                    </td>
                    <td className="px-4 py-2 font-mono">{ioc.value}</td>
                    <td className="px-4 py-2 text-[var(--text-secondary)]">
                      {ioc.context}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Export buttons */}
      <div className="flex gap-3">
        <a
          href={getExportUrl(jobId, "json")}
          className="flex items-center gap-2 px-4 py-2 bg-[var(--bg-card)] border border-[var(--border)] rounded-lg hover:border-[var(--accent-blue)] transition text-sm"
        >
          <Download size={16} /> JSON Report
        </a>
        <a
          href={getExportUrl(jobId, "text")}
          className="flex items-center gap-2 px-4 py-2 bg-[var(--bg-card)] border border-[var(--border)] rounded-lg hover:border-[var(--accent-blue)] transition text-sm"
        >
          <Download size={16} /> Text Report
        </a>
      </div>

      {/* AI Panel */}
      <AiPanel jobId={jobId} />

      {/* Notes */}
      <NotesSection jobId={jobId} />

      {/* Tool execution */}
      <div>
        <h2 className="text-lg font-semibold mb-4">Tool Execution</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {report.tool_results.map((t: any, i: number) => (
            <div
              key={i}
              className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-sm"
            >
              <div className="flex items-center gap-2 mb-1">
                <div
                  className="w-2 h-2 rounded-full"
                  style={{
                    backgroundColor: t.success
                      ? "var(--accent-green)"
                      : "var(--accent-red)",
                  }}
                />
                <span className="font-semibold">{t.tool}</span>
              </div>
              <div className="text-[var(--text-secondary)]">
                {t.duration_seconds.toFixed(2)}s
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function NotesSection({ jobId }: { jobId: string }) {
  const [note, setNote] = useState("");
  const [notes, setNotes] = useState<any[]>([]);
  const [loggedIn, setLoggedIn] = useState(false);

  useEffect(() => {
    setLoggedIn(isLoggedIn());
  }, []);

  if (!loggedIn) return null;

  const handleAdd = async () => {
    if (!note.trim()) return;
    try {
      // Note: would need upload_id, but for now we show the UI
      setNotes([...notes, { content: note, created_at: new Date().toISOString() }]);
      setNote("");
    } catch {}
  };

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
      <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <MessageSquare size={20} /> Notes
      </h2>
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Add a note about this sample..."
          value={note}
          onChange={(e) => setNote(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleAdd()}
          className="flex-1 px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg text-sm focus:outline-none focus:border-[var(--accent-blue)]"
        />
        <button
          onClick={handleAdd}
          className="px-4 py-2 bg-[var(--accent-blue)] text-white rounded-lg text-sm hover:opacity-90 transition"
        >
          Add
        </button>
      </div>
      {notes.length > 0 && (
        <div className="mt-4 space-y-2">
          {notes.map((n, i) => (
            <div key={i} className="p-3 bg-[var(--bg-secondary)] rounded-lg text-sm">
              <p>{n.content}</p>
              <p className="text-xs text-[var(--text-secondary)] mt-1">
                {new Date(n.created_at).toLocaleString()}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 text-center">
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs text-[var(--text-secondary)]">{label}</div>
    </div>
  );
}
