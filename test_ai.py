"""Test that Ollama AI is producing real responses, not just connecting."""
import os
import time

os.environ["OLLAMA_MODEL"] = "llama3.1:latest"
from core.ai.interpreter import _call_ollama, is_ai_available, get_available_models, OLLAMA_HOST, OLLAMA_MODEL

print(f"Ollama host:        {OLLAMA_HOST}")
print(f"Configured model:   {OLLAMA_MODEL}")
print(f"Reachable:          {is_ai_available()}")
print(f"Installed models:   {get_available_models()}")
print()
print("Sending live prompt to Llama 3.1...")
print()

start = time.time()
response = _call_ollama(
    "You are a senior malware analyst.",
    "If a Windows binary imports CreateRemoteThread, VirtualAllocEx, and WriteProcessMemory together, what is it doing? Answer in one sentence.",
    max_tokens=200,
)
elapsed = time.time() - start

print(f"Response in {elapsed:.1f}s:")
print(f"  > {response.strip()}")
print()
print("AI is working." if response.strip() else "AI returned empty.")
