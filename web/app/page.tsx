"use client";

import { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { uploadFile, startAnalysis } from "@/lib/api";
import { Upload, Shield, Zap, FileSearch } from "lucide-react";

export default function Home() {
  const router = useRouter();
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [status, setStatus] = useState("");

  const handleFile = useCallback(
    async (file: File) => {
      setIsUploading(true);
      try {
        setStatus("Uploading...");
        const uploadResult = await uploadFile(file);

        setStatus("Starting analysis...");
        const analysisResult = await startAnalysis(uploadResult.upload_id);

        router.push(`/analysis/${analysisResult.job_id}`);
      } catch (err) {
        setStatus(`Error: ${err instanceof Error ? err.message : "Unknown error"}`);
        setIsUploading(false);
      }
    },
    [router]
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  const onFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  return (
    <div className="flex flex-col items-center gap-12 pt-12">
      {/* Hero */}
      <div className="text-center">
        <h1 className="text-4xl font-bold mb-4">
          <span className="text-[var(--accent-blue)]">Reverse Engineering</span>
          <br />
          Automated
        </h1>
        <p className="text-[var(--text-secondary)] max-w-md">
          Drop a binary, firmware, or capture file. Deshifro runs the full RE
          pipeline and gives you a structured report.
        </p>
      </div>

      {/* Upload zone */}
      <div
        className={`
          w-full max-w-xl border-2 border-dashed rounded-xl p-12
          flex flex-col items-center gap-4 cursor-pointer transition
          ${isDragging
            ? "border-[var(--accent-blue)] bg-[var(--accent-blue)]/5"
            : "border-[var(--border)] hover:border-[var(--accent-blue)]/50"
          }
          ${isUploading ? "opacity-60 pointer-events-none" : ""}
        `}
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={onDrop}
        onClick={() => document.getElementById("file-input")?.click()}
      >
        <Upload
          size={48}
          className={isDragging ? "text-[var(--accent-blue)]" : "text-[var(--text-secondary)]"}
        />
        <p className="text-lg">
          {isUploading ? status : "Drop file here or click to browse"}
        </p>
        <p className="text-sm text-[var(--text-secondary)]">
          PE, ELF, Mach-O, PCAP, firmware images
        </p>
        <input
          id="file-input"
          type="file"
          className="hidden"
          onChange={onFileSelect}
        />
      </div>

      {/* Features */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-3xl">
        <FeatureCard
          icon={<FileSearch size={24} />}
          title="Static Analysis"
          desc="Strings, entropy, YARA, decompilation"
        />
        <FeatureCard
          icon={<Zap size={24} />}
          title="Auto Pipeline"
          desc="Detects file type, picks the right tools"
        />
        <FeatureCard
          icon={<Shield size={24} />}
          title="Threat Intel"
          desc="IOCs, MITRE ATT&CK, verdict scoring"
        />
      </div>
    </div>
  );
}

function FeatureCard({
  icon,
  title,
  desc,
}: {
  icon: React.ReactNode;
  title: string;
  desc: string;
}) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
      <div className="text-[var(--accent-blue)] mb-3">{icon}</div>
      <h3 className="font-semibold mb-1">{title}</h3>
      <p className="text-sm text-[var(--text-secondary)]">{desc}</p>
    </div>
  );
}
