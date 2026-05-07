"use client";

import { useEffect, useState } from "react";
import { getDisasm } from "@/lib/api";
import { Loader2, Code } from "lucide-react";

export function DisassemblyView({
  uploadId,
  offset,
  useAddress = false,
}: {
  uploadId: string;
  offset: number;
  useAddress?: boolean;
}) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    setError("");
    getDisasm(uploadId, offset, 256, useAddress)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [uploadId, offset, useAddress]);

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="border-b border-[var(--border)] px-4 py-2 flex items-center gap-2">
        <Code size={14} className="text-[var(--accent-blue)]" />
        <span className="text-sm font-semibold">
          Disassembly @ {useAddress ? "0x" : "+"}
          {offset.toString(16)}
        </span>
        {loading && <Loader2 size={12} className="animate-spin ml-auto" />}
      </div>

      {error && (
        <div className="p-4 text-[var(--accent-red)] text-sm">{error}</div>
      )}

      {data && (
        <pre className="p-4 font-mono text-xs overflow-x-auto whitespace-pre text-[var(--text-primary)]">
{highlightAsm(data.disassembly)}
        </pre>
      )}
    </div>
  );
}

function highlightAsm(text: string): React.ReactNode {
  if (!text) return null;
  const lines = text.split("\n");
  return lines.map((line, i) => {
    let className = "";
    // Highlight common malware-relevant instructions
    if (/\b(call|jmp|je|jne|jz|jnz|jl|jg|loop)\b/i.test(line))
      className = "text-[var(--accent-yellow)]";
    else if (/\b(rdtsc|cpuid|int 2dh|int3)\b/i.test(line))
      className = "text-[var(--accent-red)]";
    else if (/\b(xor|and|or|not|shl|shr|ror|rol)\b/i.test(line))
      className = "text-[var(--accent-purple)]";
    else if (/^;/.test(line.trim()) || /\/\//.test(line))
      className = "text-[var(--text-secondary)]";

    return (
      <div key={i} className={className}>
        {line}
      </div>
    );
  });
}
