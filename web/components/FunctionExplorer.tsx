"use client";

import { useState, useMemo } from "react";
import { Search, Tag } from "lucide-react";

const TAG_COLORS: Record<string, string> = {
  network: "var(--accent-blue)",
  file: "var(--accent-green)",
  process: "var(--accent-yellow)",
  injection: "var(--accent-red)",
  crypto: "var(--accent-purple)",
  registry: "var(--accent-blue)",
  anti_debug: "var(--accent-red)",
  "anti-debug": "var(--accent-red)",
  evasion: "var(--accent-yellow)",
};

export function FunctionExplorer({
  functions,
  onSelect,
  selectedAddress,
}: {
  functions: any[];
  onSelect: (func: any) => void;
  selectedAddress?: number;
}) {
  const [search, setSearch] = useState("");
  const [filterInteresting, setFilterInteresting] = useState(false);

  const filtered = useMemo(() => {
    let result = functions;
    if (filterInteresting) {
      result = result.filter((f) => f.is_interesting);
    }
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (f) =>
          f.name?.toLowerCase().includes(q) ||
          f.address?.toString(16).includes(q) ||
          f.tags?.some((t: string) => t.includes(q))
      );
    }
    // Show interesting first
    return [...result].sort((a, b) => {
      if (a.is_interesting !== b.is_interesting) return b.is_interesting ? 1 : -1;
      return (a.address || 0) - (b.address || 0);
    });
  }, [functions, search, filterInteresting]);

  if (!functions || functions.length === 0) {
    return (
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 text-sm text-[var(--text-secondary)]">
        No function data available. Install radare2 or Ghidra to enable disassembly.
      </div>
    );
  }

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="border-b border-[var(--border)] p-3 space-y-2">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)]" />
          <input
            type="text"
            placeholder="Search functions, addresses, tags..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-[var(--bg-secondary)] border border-[var(--border)] rounded text-xs focus:outline-none"
          />
        </div>
        <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
          <input
            type="checkbox"
            checked={filterInteresting}
            onChange={(e) => setFilterInteresting(e.target.checked)}
          />
          Only show interesting (calls suspicious APIs)
        </label>
      </div>

      <div className="max-h-[400px] overflow-y-auto">
        {filtered.map((func, i) => (
          <button
            key={i}
            onClick={() => onSelect(func)}
            className={`w-full text-left px-3 py-2 text-xs border-b border-[var(--border)]/30 hover:bg-[var(--bg-secondary)] transition ${
              selectedAddress === func.address ? "bg-[var(--bg-secondary)]" : ""
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="text-[var(--accent-blue)] font-mono shrink-0 w-20">
                0x{func.address?.toString(16) || "?"}
              </span>
              <span className="font-mono truncate flex-1">{func.name}</span>
              {func.is_interesting && (
                <span
                  className="text-[10px] px-1.5 py-0.5 rounded uppercase shrink-0"
                  style={{
                    color: "var(--accent-red)",
                    backgroundColor: "var(--accent-red)20",
                  }}
                >
                  ★
                </span>
              )}
            </div>
            {func.tags && func.tags.length > 0 && (
              <div className="flex gap-1 mt-1 ml-22 flex-wrap">
                {func.tags.map((tag: string) => (
                  <span
                    key={tag}
                    className="text-[10px] px-1.5 py-0.5 rounded"
                    style={{
                      color: TAG_COLORS[tag] || "var(--text-secondary)",
                      backgroundColor: `${TAG_COLORS[tag] || "var(--text-secondary)"}20`,
                    }}
                  >
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </button>
        ))}
      </div>

      <div className="border-t border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)]">
        {filtered.length} of {functions.length} functions
      </div>
    </div>
  );
}
