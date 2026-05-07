"use client";

import { useEffect, useState } from "react";
import { getHex } from "@/lib/api";
import { ChevronLeft, ChevronRight, Loader2 } from "lucide-react";

const PAGE_SIZE = 256;

export function HexView({
  uploadId,
  initialOffset = 0,
}: {
  uploadId: string;
  initialOffset?: number;
}) {
  const [offset, setOffset] = useState(initialOffset);
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    setError("");
    getHex(uploadId, offset, PAGE_SIZE)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [uploadId, offset]);

  if (error) {
    return <div className="text-[var(--accent-red)] text-sm">{error}</div>;
  }

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
      {/* Toolbar */}
      <div className="border-b border-[var(--border)] px-4 py-2 flex items-center gap-3">
        <button
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          disabled={offset === 0}
          className="p-1 rounded hover:bg-[var(--bg-secondary)] disabled:opacity-30"
        >
          <ChevronLeft size={14} />
        </button>
        <input
          type="text"
          value={`0x${offset.toString(16)}`}
          onChange={(e) => {
            const val = parseInt(e.target.value.replace(/^0x/, ""), 16);
            if (!isNaN(val)) setOffset(val);
          }}
          className="font-mono text-xs bg-[var(--bg-secondary)] px-2 py-1 rounded w-32 focus:outline-none"
        />
        <button
          onClick={() => setOffset(offset + PAGE_SIZE)}
          disabled={data && offset + PAGE_SIZE >= data.file_size}
          className="p-1 rounded hover:bg-[var(--bg-secondary)] disabled:opacity-30"
        >
          <ChevronRight size={14} />
        </button>
        <span className="text-xs text-[var(--text-secondary)] ml-auto">
          {data && `${(data.file_size / 1024).toFixed(1)} KB total`}
        </span>
        {loading && <Loader2 size={12} className="animate-spin" />}
      </div>

      {/* Hex grid */}
      {data && (
        <div className="p-4 font-mono text-xs overflow-x-auto">
          <div className="text-[var(--text-secondary)] flex gap-4 pb-2 border-b border-[var(--border)]/50">
            <span className="w-16">Offset</span>
            <span className="flex-1">
              {Array.from({ length: 16 }, (_, i) => i.toString(16).padStart(2, "0")).join(" ")}
            </span>
            <span className="w-16">ASCII</span>
          </div>
          {data.rows.map((row: any, i: number) => (
            <div key={i} className="flex gap-4 py-0.5 hover:bg-[var(--bg-secondary)]">
              <span className="w-16 text-[var(--accent-blue)]">
                {row.offset.toString(16).padStart(8, "0")}
              </span>
              <span className="flex-1 text-[var(--text-primary)]">{row.hex}</span>
              <span className="w-16 text-[var(--accent-purple)]">{row.ascii}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
