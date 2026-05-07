"use client";

import { useState } from "react";
import { Binary, Code, FileCode } from "lucide-react";
import { FunctionExplorer } from "./FunctionExplorer";
import { DisassemblyView } from "./DisassemblyView";
import { HexView } from "./HexView";

type Tab = "functions" | "disasm" | "hex";

export function InspectPanel({
  uploadId,
  functions,
}: {
  uploadId: string;
  functions: any[];
}) {
  const [tab, setTab] = useState<Tab>("functions");
  const [selectedFunc, setSelectedFunc] = useState<any>(null);
  const [hexOffset, setHexOffset] = useState(0);

  const handleSelect = (func: any) => {
    setSelectedFunc(func);
    setTab("disasm");
  };

  return (
    <div>
      <h2 className="text-lg font-semibold mb-4">Inspect</h2>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-[var(--border)] mb-4">
        <TabButton
          active={tab === "functions"}
          onClick={() => setTab("functions")}
          icon={<FileCode size={14} />}
          label={`Functions (${functions?.length || 0})`}
        />
        <TabButton
          active={tab === "disasm"}
          onClick={() => setTab("disasm")}
          icon={<Code size={14} />}
          label="Disassembly"
        />
        <TabButton
          active={tab === "hex"}
          onClick={() => setTab("hex")}
          icon={<Binary size={14} />}
          label="Hex"
        />
      </div>

      {tab === "functions" && (
        <FunctionExplorer
          functions={functions || []}
          onSelect={handleSelect}
          selectedAddress={selectedFunc?.address}
        />
      )}

      {tab === "disasm" && (
        <div className="space-y-3">
          {selectedFunc ? (
            <>
              <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-sm">
                <div className="font-mono">{selectedFunc.name}</div>
                <div className="text-xs text-[var(--text-secondary)] mt-1">
                  Address: 0x{selectedFunc.address?.toString(16)} · Size: {selectedFunc.size} bytes
                </div>
                {selectedFunc.tags && selectedFunc.tags.length > 0 && (
                  <div className="flex gap-1 mt-2 flex-wrap">
                    {selectedFunc.tags.map((t: string) => (
                      <span
                        key={t}
                        className="text-xs px-2 py-0.5 bg-[var(--bg-secondary)] rounded"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              {selectedFunc.code ? (
                <pre className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                  {selectedFunc.code}
                </pre>
              ) : (
                <DisassemblyView
                  uploadId={uploadId}
                  offset={selectedFunc.address}
                  useAddress={true}
                />
              )}
            </>
          ) : (
            <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 text-sm text-[var(--text-secondary)] text-center">
              Pick a function from the list to view its disassembly.
            </div>
          )}
        </div>
      )}

      {tab === "hex" && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-[var(--text-secondary)]">Jump to offset:</span>
            <input
              type="text"
              placeholder="0x0"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  const val = parseInt((e.target as HTMLInputElement).value.replace(/^0x/, ""), 16);
                  if (!isNaN(val)) setHexOffset(val);
                }
              }}
              className="font-mono text-xs bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 rounded w-32 focus:outline-none"
            />
          </div>
          <HexView uploadId={uploadId} initialOffset={hexOffset} key={hexOffset} />
        </div>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2 text-sm border-b-2 transition ${
        active
          ? "border-[var(--accent-blue)] text-[var(--accent-blue)]"
          : "border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
      }`}
    >
      {icon}
      {label}
    </button>
  );
}
