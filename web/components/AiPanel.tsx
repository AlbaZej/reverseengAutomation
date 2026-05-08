"use client";

import { useEffect, useState } from "react";
import { aiExplain, aiAsk, aiGenerateYara, getAiStatus } from "@/lib/api";
import { Cpu, MessageSquare, FileCode, Loader2 } from "lucide-react";

const SUGGESTED_QUESTIONS = [
  "Is this packed?",
  "Does it use process injection?",
  "What anti-debug techniques are used?",
  "Does it connect to a C2?",
  "What persistence mechanism does it use?",
  "What is the verdict?",
];

export function AiPanel({ jobId }: { jobId: string }) {
  const [aiAvailable, setAiAvailable] = useState<boolean | null>(null);
  const [explanation, setExplanation] = useState<any>(null);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");
  const [yaraRule, setYaraRule] = useState("");
  const [loading, setLoading] = useState("");

  useEffect(() => {
    getAiStatus().then((d) => setAiAvailable(d.available));
  }, []);

  const handleExplain = async () => {
    setLoading("explain");
    try {
      const result = await aiExplain(jobId);
      if (result.error && !result.summary) {
        setExplanation({
          summary: `AI request failed: ${result.error}`,
        });
      } else {
        setExplanation(result);
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      setExplanation({
        summary: `Request failed: ${msg}.`,
      });
    } finally {
      setLoading("");
    }
  };

  const askWith = async (q: string) => {
    if (!q.trim()) return;
    setLoading("ask");
    try {
      const result = await aiAsk(jobId, q);
      setAnswer(result.answer || "No answer available");
    } catch {
      setAnswer("Failed to get answer");
    } finally {
      setLoading("");
    }
  };

  const handleAsk = () => askWith(question);

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

  if (aiAvailable === null) return null;

  const isFallback = explanation?.source === "fallback";

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Cpu size={20} className="text-[var(--accent-blue)]" /> AI Analysis
        </h2>
        <div className="flex items-center gap-2 text-xs">
          <div
            className="w-2 h-2 rounded-full"
            style={{
              backgroundColor: aiAvailable
                ? "var(--accent-green)"
                : "var(--accent-yellow)",
            }}
          />
          <span className="text-[var(--text-secondary)]">
            {aiAvailable ? "Ollama (local LLM)" : "Fallback mode (no Ollama)"}
          </span>
        </div>
      </div>

      {!aiAvailable && (
        <div className="text-xs text-[var(--text-secondary)] p-2 bg-[var(--bg-secondary)] rounded">
          Ollama isn't running. Responses are generated from the deterministic findings.
          To get richer summaries: install Ollama from{" "}
          <a
            href="https://ollama.com/download"
            target="_blank"
            rel="noopener"
            className="text-[var(--accent-blue)] hover:underline"
          >
            ollama.com/download
          </a>{" "}
          and run <code className="text-[var(--accent-blue)]">ollama pull llama3.1:8b</code>.
        </div>
      )}

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
          <>
            <div className="mt-3 p-4 bg-[var(--bg-secondary)] rounded-lg text-sm whitespace-pre-wrap">
              {explanation.summary}
            </div>
            {isFallback && (
              <div className="text-xs text-[var(--text-secondary)] mt-1">
                ↑ Generated from deterministic findings (no LLM)
              </div>
            )}
            {explanation.next_steps?.length > 0 && (
              <div className="mt-2 text-sm">
                <span className="text-[var(--text-secondary)]">Next steps:</span>
                <ul className="list-disc list-inside mt-1 text-[var(--text-secondary)]">
                  {explanation.next_steps.map((s: string, i: number) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </div>

      {/* Suggested questions chips */}
      <div>
        <div className="text-xs text-[var(--text-secondary)] mb-2">Suggested questions:</div>
        <div className="flex flex-wrap gap-2 mb-3">
          {SUGGESTED_QUESTIONS.map((sq) => (
            <button
              key={sq}
              onClick={() => {
                setQuestion(sq);
                askWith(sq);
              }}
              disabled={loading === "ask"}
              className="text-xs px-3 py-1.5 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-full hover:border-[var(--accent-blue)] hover:text-[var(--accent-blue)] transition disabled:opacity-50"
            >
              {sq}
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Or ask your own question..."
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
