"use client";

import { useState } from "react";
import { aiExplain, aiAsk, aiGenerateYara, getAiStatus } from "@/lib/api";
import { Cpu, MessageSquare, FileCode, Loader2 } from "lucide-react";

export function AiPanel({ jobId }: { jobId: string }) {
  const [aiAvailable, setAiAvailable] = useState<boolean | null>(null);
  const [explanation, setExplanation] = useState<any>(null);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");
  const [yaraRule, setYaraRule] = useState("");
  const [loading, setLoading] = useState("");

  // Check AI status on first render
  useState(() => {
    getAiStatus().then((d) => setAiAvailable(d.available));
  });

  if (aiAvailable === null) return null;

  if (!aiAvailable) {
    return (
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-2 flex items-center gap-2">
          <Cpu size={20} className="text-[var(--text-secondary)]" /> AI Analysis
        </h2>
        <p className="text-sm text-[var(--text-secondary)]">
          Ollama is not running. AI features run locally — your data never leaves your machine.
        </p>
        <ol className="text-xs text-[var(--text-secondary)] mt-3 space-y-1 list-decimal list-inside">
          <li>
            Install Ollama:{" "}
            <a
              href="https://ollama.com/download"
              target="_blank"
              rel="noopener"
              className="text-[var(--accent-blue)] hover:underline"
            >
              ollama.com/download
            </a>
          </li>
          <li>
            Pull a model: <code className="text-[var(--accent-blue)]">ollama pull llama3.1:8b</code>
          </li>
          <li>Ollama runs automatically — refresh this page</li>
        </ol>
      </div>
    );
  }

  const handleExplain = async () => {
    setLoading("explain");
    try {
      const result = await aiExplain(jobId);
      // Surface the error field if the backend returned one
      if (result.error) {
        setExplanation({
          summary: `AI request failed: ${result.error}`,
        });
      } else {
        setExplanation(result);
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      setExplanation({ summary: `Request failed: ${msg}. Open the browser DevTools → Network tab to see the response.` });
    } finally {
      setLoading("");
    }
  };

  const handleAsk = async () => {
    if (!question.trim()) return;
    setLoading("ask");
    try {
      const result = await aiAsk(jobId, question);
      setAnswer(result.answer || "No answer available");
    } catch {
      setAnswer("Failed to get answer");
    } finally {
      setLoading("");
    }
  };

  const handleYara = async () => {
    setLoading("yara");
    try {
      const result = await aiGenerateYara(jobId);
      setYaraRule(result.rule || "Failed to generate rule");
    } catch {
      setYaraRule("Failed to generate YARA rule");
    } finally {
      setLoading("");
    }
  };

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-6">
      <h2 className="text-lg font-semibold flex items-center gap-2">
        <Cpu size={20} className="text-[var(--accent-blue)]" /> AI Analysis
      </h2>

      {/* Explain button */}
      <div>
        <button
          onClick={handleExplain}
          disabled={loading === "explain"}
          className="flex items-center gap-2 px-4 py-2 bg-[var(--accent-blue)]/20 border border-[var(--accent-blue)]/40 rounded-lg text-sm text-[var(--accent-blue)] hover:bg-[var(--accent-blue)]/30 transition disabled:opacity-50"
        >
          {loading === "explain" ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <Cpu size={14} />
          )}
          Explain this binary
        </button>
        {explanation?.summary && (
          <div className="mt-3 p-4 bg-[var(--bg-secondary)] rounded-lg text-sm whitespace-pre-wrap">
            {explanation.summary}
          </div>
        )}
        {explanation?.next_steps?.length > 0 && (
          <div className="mt-2 text-sm">
            <span className="text-[var(--text-secondary)]">Next steps:</span>
            <ul className="list-disc list-inside mt-1 text-[var(--text-secondary)]">
              {explanation.next_steps.map((s: string, i: number) => (
                <li key={i}>{s}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Ask a question */}
      <div>
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Ask about this binary..."
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAsk()}
            className="flex-1 px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg text-sm focus:outline-none focus:border-[var(--accent-blue)]"
          />
          <button
            onClick={handleAsk}
            disabled={loading === "ask" || !question.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg text-sm hover:border-[var(--accent-blue)] transition disabled:opacity-50"
          >
            {loading === "ask" ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <MessageSquare size={14} />
            )}
            Ask
          </button>
        </div>
        {answer && (
          <div className="mt-3 p-4 bg-[var(--bg-secondary)] rounded-lg text-sm whitespace-pre-wrap">
            {answer}
          </div>
        )}
      </div>

      {/* Generate YARA */}
      <div>
        <button
          onClick={handleYara}
          disabled={loading === "yara"}
          className="flex items-center gap-2 px-4 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg text-sm hover:border-[var(--accent-purple)] transition disabled:opacity-50"
        >
          {loading === "yara" ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <FileCode size={14} />
          )}
          Generate YARA rule
        </button>
        {yaraRule && (
          <pre className="mt-3 p-4 bg-[var(--bg-secondary)] rounded-lg text-xs font-mono overflow-x-auto whitespace-pre-wrap">
            {yaraRule}
          </pre>
        )}
      </div>
    </div>
  );
}
