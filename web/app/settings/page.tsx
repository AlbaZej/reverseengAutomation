"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { createApiKey, getMe, isLoggedIn, logout, getAiStatus } from "@/lib/api";
import { Key, LogOut, Cpu } from "lucide-react";

export default function SettingsPage() {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [aiAvailable, setAiAvailable] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [createdKey, setCreatedKey] = useState("");

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    getMe().then(setUser);
    getAiStatus().then((d) => setAiAvailable(d.available));
  }, [router]);

  const handleCreateKey = async () => {
    try {
      const result = await createApiKey(newKeyName || "default");
      setCreatedKey(result.api_key);
      setNewKeyName("");
    } catch {
      alert("Failed to create API key");
    }
  };

  const handleLogout = () => {
    logout();
    router.push("/");
  };

  return (
    <div className="max-w-2xl space-y-8">
      <h1 className="text-2xl font-bold">Settings</h1>

      {/* Profile */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Profile</h2>
        {user && (
          <div className="space-y-2 text-sm">
            <div>
              <span className="text-[var(--text-secondary)]">Email: </span>
              {user.email}
            </div>
            <div>
              <span className="text-[var(--text-secondary)]">Auth: </span>
              via {user.via}
            </div>
          </div>
        )}
        <button
          onClick={handleLogout}
          className="mt-4 flex items-center gap-2 px-4 py-2 border border-[var(--accent-red)]/50 text-[var(--accent-red)] rounded-lg text-sm hover:bg-[var(--accent-red)]/10 transition"
        >
          <LogOut size={14} /> Sign out
        </button>
      </div>

      {/* API Keys */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Key size={20} /> API Keys
        </h2>
        <p className="text-sm text-[var(--text-secondary)] mb-4">
          Use API keys to access Deshifro from scripts, CI/CD, or other tools.
        </p>

        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Key name (optional)"
            value={newKeyName}
            onChange={(e) => setNewKeyName(e.target.value)}
            className="flex-1 px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg text-sm focus:outline-none"
          />
          <button
            onClick={handleCreateKey}
            className="px-4 py-2 bg-[var(--accent-blue)] text-white rounded-lg text-sm font-semibold hover:opacity-90 transition"
          >
            Generate
          </button>
        </div>

        {createdKey && (
          <div className="mt-4 p-4 bg-[var(--accent-green)]/10 border border-[var(--accent-green)]/30 rounded-lg">
            <p className="text-sm font-semibold text-[var(--accent-green)] mb-1">
              API Key Created
            </p>
            <code className="text-xs font-mono break-all">{createdKey}</code>
            <p className="text-xs text-[var(--text-secondary)] mt-2">
              Copy this now — it won't be shown again.
            </p>
          </div>
        )}

        <div className="mt-4 p-3 bg-[var(--bg-secondary)] rounded-lg text-sm text-[var(--text-secondary)]">
          <p className="font-mono text-xs">
            curl -H "Authorization: Bearer dshf_..." {typeof window !== "undefined" ? window.location.origin : ""}/api/upload
          </p>
        </div>
      </div>

      {/* AI Status */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Cpu size={20} /> AI Features
        </h2>
        <div className="flex items-center gap-3">
          <div
            className="w-3 h-3 rounded-full"
            style={{
              backgroundColor: aiAvailable
                ? "var(--accent-green)"
                : "var(--accent-red)",
            }}
          />
          <span className="text-sm">
            {aiAvailable
              ? "AI features enabled (ANTHROPIC_API_KEY configured)"
              : "AI features disabled — set ANTHROPIC_API_KEY on the server"}
          </span>
        </div>
        <p className="text-sm text-[var(--text-secondary)] mt-3">
          When enabled, AI can explain analysis results, suggest function names,
          generate YARA rules, and answer questions about samples.
        </p>
      </div>
    </div>
  );
}
