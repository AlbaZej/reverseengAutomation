# Building Deshifro — Part 1: Planning a Static Malware Analysis Project

When my malware analysis professor first walked us through Cutter, opening a binary and clicking around the disassembly, I remember thinking two things at once: this is fascinating, and this will take forever. By the time you imagine yourself three samples in, you start noticing that the first thirty minutes of every analysis would look identical — extract strings, eyeball the imports, check entropy, hash the file, look it up on VirusTotal, scan with YARA. Same routine, every time, before any actual reverse engineering begins.

So I'm starting a project to automate that boring part. I'm calling it **Deshifro** — *decipher* in Albanian — and this blog post is the planning stage for it. I haven't run the empirical evaluation yet. I haven't proven any of this works. The point of Part 1 is to lay out exactly what I intend to do, what I expect to find, and what I'm prepared for to go wrong. Part 2, which I'll write after I actually do the experiments, will be the results — including the parts that don't pan out the way I'm currently predicting.

This is a planning post. Read it as such.

---

## 1. Project Overview

### What I'm planning to reverse engineer

Two things, intentionally chosen to feed each other:

**The first target is going to be a corpus of Windows malware samples** — PE32 and PE32+ executables I plan to pull from MalwareBazaar, the public repository run by abuse.ch. I want a small, deliberately mixed set: a few samples from each of the well-known commodity families (Emotet, Qakbot, AgentTesla, RedLine), plus a few generic loaders and droppers. Mostly C/C++ binaries, with a Go and a .NET binary thrown in for variety. I'm thinking around fifty malicious samples for the evaluation set.

**The second target is the analysis workflow itself.** That's the meta-angle, and it's the part I find most interesting. I want to take the implicit knowledge that experienced malware analysts use — the small mental routines they go through almost without thinking — and make those routines explicit in code. I'm essentially trying to reverse engineer the analyst, not just the malware.

These two targets are designed to inform each other. Every sample I look at will teach me a heuristic worth encoding. Every heuristic I encode will get tested against the next sample.

### Broader domain and context

The project sits inside **static malware analysis on Windows**. *Static* meaning the analysis is done by examining the binary, not by running it. *Windows* because that's still where the vast majority of mass-deployed commodity malware lives, and because both my course's textbook (Sikorski & Honig, *Practical Malware Analysis*) and our class material use Windows as the primary working example.

The adjacent domain is **automated triage** — how to take a stream of incoming samples (from a SOC, an incident response engagement, a honeypot) and rapidly sort them by priority. That's where the work has practical relevance even if my own interest is more academic.

### Why I chose this

Three honest reasons.

First, **the curriculum keeps showing me the same patterns over and over.** Chapter after chapter of Sikorski/Honig points to the same handful of techniques: process injection, API hashing, GetPC tricks, packers, anti-debug. If those techniques are universal enough that a textbook teaches them as universal, they should be detectable mechanically. I want to find out whether that intuition is correct.

Second, **there's a product gap I think is worth filling.** The free tools (Ghidra, Cutter, radare2) require expertise to use well. The enterprise platforms (Joe Sandbox, Hybrid Analysis at the high tier, FireEye AX) cost thousands per seat per year. There's very little in the middle for students or small teams. If Deshifro ends up being useful to other students, that would be a nice secondary outcome.

Third — and I'll be straightforward — **I learn better by building things than by writing about them.** I could write a single-sample analysis of one piece of malware and that would satisfy the assignment. But I'd retain more by trying to encode what I've learned into a working pipeline and then measuring how well that encoding holds up. The blog post is partly the writeup my class requires and partly accountability for finishing the empirical work.

---

## 2. Research Question and Goal

### What I want to validate

The core research question I'm setting up to answer is:

> **Can a deterministic static-analysis pipeline, built from open-source tooling and a small set of well-chosen heuristics, produce verdicts (clean / suspicious / malicious) that agree with VirusTotal's consensus on a representative corpus of Windows binaries — and do so without an unacceptable false-positive rate on known-good system binaries?**

The "known-good" half of that question matters as much as the "malicious" half. I'm specifically interested in the false-positive problem because that's what kills tools in practice. If my pipeline tells you `notepad.exe` is malicious, you stop trusting it within ten minutes. So I'm setting up the experiment to measure both directions: detection on real malware *and* restraint on benign system binaries.

I expect this to be one of the harder calibration problems. Notepad legitimately uses `RegSetValueExW` to save preferences and `IsDebuggerPresent` for exception handling. Calculator legitimately uses cryptographic APIs. Most installed Windows binaries import dozens of "suspicious-looking" APIs for entirely benign reasons. A good pipeline has to recognize that single-API-category usage is not a useful signal — only *combinations* of categories, especially when paired with high-entropy regions or YARA matches, should escalate the verdict.

### Sub-questions I want to test

- **Which signals carry the most information?** My current intuition is that YARA pattern matches and entropy-based packing detection will dominate, while single-API-category detection will turn out to be noise. I want to test this with an ablation — turn each signal off, measure how much accuracy drops.
- **Can we cluster samples into families using only static features?** If imports + strings + entropy distributions are family-specific enough, you should be able to take a folder of unlabeled samples and group them into families without ever running them. There's prior work on this using fuzzy hashes (TLSH, ssdeep). I want to see if it generalizes to the simpler features Deshifro will extract.
- **How much value does an AI explanation layer add?** I'm planning to run a local Llama 3.1 model via Ollama to produce natural-language summaries of analysis results. The question is whether a small local model is up to the task, or whether 8B parameters is fundamentally too few for this kind of grounded reasoning. I'll measure this qualitatively in Part 2 by comparing AI summaries to my own manual ones on a held-out set.

### What counts as success

For Part 2, I'd consider the project successful if I can show:

- A confusion matrix on at least 50 known-malicious samples and 50 known-benign Windows binaries, with measured TPR, FPR, and F1.
- The Notepad-style false positive (and its analogs — Calculator, signed Microsoft DLLs, the Visual Studio installer, common open-source apps) is not flagged as malicious.
- For at least one malware family, an auto-generated YARA rule from a single sample successfully detects other samples in the same family without false-flagging unrelated samples.
- An honest discussion of the failure modes — which patterns the pipeline misses, where it over-flags, where the AI helps versus where it hurts.

I expect partial success rather than full. A calibrated tool that works on textbook patterns (process injection, packed binaries, embedded shellcode) but breaks down on samples using techniques I haven't modeled yet (control-flow flattening, custom API hashing algorithms, multi-stage runtime decryption) would still be a meaningful result — it would tell me where the limits are.

---

## 3. Background Information

I'm assuming readers have a CS background but not necessarily malware-analysis experience. Here's the minimum needed to follow the rest of this series.

### What's inside a Windows PE binary

Every executable I'll be analyzing has roughly the same skeleton:

- A **DOS header** starting with the bytes `MZ`. Vestigial — left over from the 16-bit era — but still required by the loader.
- A **PE header** with the Machine field (`0x014C` for x86, `0x8664` for x86_64) and characteristics flags telling you whether it's an EXE, a DLL, or a driver.
- An **Optional Header** with the entry point address, the image base, section alignment, and a directory of important tables.
- A **section table** — typically `.text` for code, `.rdata` for read-only data, `.data` for writable globals, `.rsrc` for resources. Packers introduce their own sections like `UPX0`, `.aspack`, `.vmp0`, and those names alone are a strong tell.
- An **Import Address Table** (IAT) — a directory of every function from every DLL the binary depends on. This is the single richest signal source in static analysis. A binary that imports `CreateRemoteThread`, `VirtualAllocEx`, and `WriteProcessMemory` together is almost certainly attempting process injection.
- An **Export Table** — symbols the binary exposes, mostly relevant if it's a DLL.

### Packers in one paragraph

A packer takes a normal PE, compresses or encrypts the original `.text` section, and prepends a small unpacking stub. When the binary runs, the stub allocates memory, decrypts the original code into it, fixes up imports, and jumps to the original entry point. From a static-analysis perspective, all you ever see is the unpacking stub — the actual malware logic is invisible until execution. The most common packers in the wild are UPX (trivial — `upx -d` reverses it), ASPack, Themida, VMProtect, and Enigma. The last two are commercial-grade obfuscators with academic papers written about defeating them.

### x86 patterns that recur in malware

These are pulled directly from the Sikorski/Honig chapters on shellcode and anti-analysis. Each one is a recognizable byte sequence:

- **GetPC** — the shellcode trick of doing `CALL +5; POP eax` to recover the current instruction pointer. Position-independent shellcode needs this because it doesn't know where in memory it has been loaded.
- **API hash resolution** — instead of importing `LoadLibraryA` by name (which would show up in the IAT), the binary walks `kernel32.dll`'s export table at runtime, hashes each function name with something like `ROR EDX, 13; ADD EDX`, and matches against a precomputed table. The IAT looks empty. The strings look empty. The malware still calls every API it wants.
- **PEB walk** — accessing `fs:[0x30]` to read the Process Environment Block, then walking the loader data list to find loaded DLLs without using documented APIs.
- **Anti-debug** — `RDTSC` to detect debugger-induced timing slowdowns, `INT 2Dh` for the NtRaiseException trick, `IN DX, EAX` against the VMware backdoor port.

These patterns are noisy individually — modern compilers emit short `CALL/POP` pairs all the time for ASLR-friendly code generation — but the *combination* of two or three of them is a strong signal. That's a key design constraint for the pipeline I'm planning: detect combinations, not individual patterns.

### Tools I'll be building on

- **radare2 / Cutter** — open-source disassembly framework. r2 is the engine; Cutter is the Qt GUI we use in class. I'm planning to use r2 directly via `r2pipe` for headless analysis.
- **Ghidra** — NSA's open-source counterpart with a respectable decompiler. Heavy install but accurate.
- **YARA** — pattern-matching DSL. Rules are short, readable, and shareable, and the format is the standard for sharing malware signatures across the security industry.
- **binwalk** — for embedded content and firmware (more relevant if I extend to firmware later).
- **MITRE ATT&CK** — taxonomy mapping observed techniques to common IDs like T1055 (Process Injection) or T1027 (Obfuscated Files). I'll tag findings with these so the report speaks the same language as the rest of the security industry.

### Prior work and adjacent products

The closest commercial product to what I'm planning is **Joe Sandbox** or **Hybrid Analysis**. Their core insight — produce one report combining static, dynamic, and threat-intel signals — is the model I'm following on the static side. I'm explicitly *not* doing dynamic analysis in this project; that's a much larger scope and would require sandbox infrastructure I don't want to build.

On the academic side, I've looked at the **Caring Caribou** family of tools (different domain — automotive — but the same orchestration philosophy), the design of **Cuckoo Sandbox** for the dynamic-analysis comparison, and various papers on automated malware classification using static features. None of them are quite the project I want to build, but each one informed parts of the design.

---

## 4. Initial Reconnaissance

### What's already available

A surprising amount, which is part of what makes this project tractable as a student.

**Sample sources.** MalwareBazaar by abuse.ch is the best public corpus I know of. Over a million samples, tagged by family, distributed as AES-encrypted ZIPs with the password `infected` so they don't accidentally trigger AV on download. I'm planning to pull around fifty samples from there for the malicious half of the evaluation set.

**Ground-truth labels.** VirusTotal's hash lookup gives a consensus verdict from 70+ AV engines. I'll use that as the benchmark for measuring pipeline accuracy. I'm aware VT isn't perfect — engines disagree, the consensus drifts as new signatures land — but for academic purposes it's the best ground truth I can get without commissioning a labeling effort myself.

**Documentation.** Microsoft's official PE/COFF specification is public, and the LIEF and `pefile` libraries provide well-documented programmatic access to it. MITRE ATT&CK is fully open. The YARA rule format has good documentation and there's an active community publishing rules.

**Tools.** Everything I need is open-source and free. radare2 binaries for Windows are on GitHub. Ollama installs in two clicks. Python has the rest.

### What I plan to use as input

For the empirical evaluation in Part 2, I'm planning two sets:

- **50 known-malicious samples**, drawn from MalwareBazaar across 4–5 family tags. Pulling across multiple families, rather than fifty samples of one family, because I want to test whether the pipeline generalizes or whether it just memorizes one family's quirks.
- **50 known-benign samples**, drawn from `C:\Windows\System32\` (signed Microsoft binaries), popular open-source apps (7-Zip, VLC, Notepad++), and the binaries that ship with developer tools like Visual Studio. These form the false-positive test set.

I'll cross-reference every sample against VirusTotal before treating its label as ground truth. Anything ambiguous gets dropped from the evaluation set.

### What's unknown

I expect to learn a few things only by running the experiment:

- **Whether the heuristics generalize.** I'm almost certainly going to overfit on whichever family I look at first. The held-out test set is what protects against this.
- **How accurate VirusTotal's consensus is on edge cases.** Some samples might have 10/70 detections. Is that malicious or noise? I'll need a tiebreak rule before running the evaluation, probably "≥5 detections counts as malicious for our purposes."
- **Whether the AI explanation layer is net-positive.** A local 8B-parameter model is going to hallucinate sometimes. The question is whether that hallucination rate is low enough for the explanations to be useful, or whether they'll be misleading often enough that I should drop the feature for Part 2's evaluation.
- **How much packed samples will degrade the verdict accuracy.** If half my malicious samples are packed and the pipeline can't see past the unpacking stub, I'll be measuring something close to "can the pipeline detect packing" rather than "can the pipeline detect malice." I'll need to report metrics separately for packed vs unpacked subsets.

---

## 5. Challenges and Constraints

### Technical obstacles I'm preparing for

**Packed and obfuscated samples.** When the malware is encrypted until runtime, there's nothing for a static pipeline to look at except the unpacking stub. I'm planning to handle this by flagging the case honestly ("appears packed — analysis limited") rather than guessing, and reporting metrics separately for packed and unpacked samples in Part 2.

**False positives are worse than false negatives.** This is an opinion, but it's the design principle I plan to calibrate around. If a tool labels Notepad as malicious, users stop trusting it within ten minutes. If a tool misses one new variant of an obscure family, users assume it just hasn't been updated yet. I'd rather miss some real samples than poison user trust. That bias will show up in my verdict thresholds — I plan to set them conservatively and accept the lower TPR.

**AES-encrypted archives.** MalwareBazaar's ZIPs use AES-256 encryption. Python's standard `zipfile` module only handles legacy ZipCrypto, not AES — which would make extraction silently fail with a "wrong password" error even when the password is correct. I'll need to use `pyzipper` or shell out to `7z` to handle AES properly. Worth noting before I'm halfway through development and confused about why my correct passwords don't work.

**LLM hallucination.** A local 8B-parameter model will confidently invent findings if its prompt isn't carefully grounded in the deterministic data. I'm planning to address this with explicit instructions in the system prompt (don't invent findings, align summary with verdict, common Windows APIs alone aren't malicious indicators), but I'm not sure that will fully fix it. If the hallucination rate stays high, I may end up disabling the AI summary for the formal evaluation and reporting it as a separate qualitative assessment.

### Legal, ethical, safety constraints

**Sample handling.** All samples will come from MalwareBazaar under their terms of use, which permit research distribution. I won't redistribute samples through this blog or through the Deshifro repository. Sample files will live in a directory listed in `.gitignore` and will never be committed.

**No execution under any circumstances.** This is a hard project-level constraint and will be enforced architecturally — there's no sandbox, no runtime, no execution path in the code. The pipeline opens samples for reading only and never invokes them. That eliminates almost all of the safety risk, but I want to be explicit about the constraint because static-only is a real limitation, not just a precaution.

**Local-only AI.** I'm choosing a local LLM (Ollama running on `localhost`) over a cloud one (Claude, GPT, Gemini). The reason isn't cost — it's operational security. Sending malware strings, hashes, or file metadata to a cloud model means those samples touch a third-party service that has logging policies, abuse-detection pipelines, and threat-actor monitoring. For samples that might be active in the wild, that's a real concern. Keeping inference local is the safer default, even though it means accepting a smaller and less capable model.

**Host hygiene.** The development machine for this project won't host other user accounts, won't be used for personal banking or email, and will have its own fresh Ollama install. This isn't paranoia — it's recognition that bugs in unpacking libraries do occasionally exist, and I'd rather not be the case study where a static analyzer accidentally executes malicious code through a parsing bug.

### Tooling and environmental constraints

**Cross-platform support is awkward.** binwalk is Linux-friendly and Windows-hostile. radare2 runs everywhere but the Windows build is sometimes a release behind. Frida runs everywhere but its Python bindings are finicky on Windows. My current development environment is Windows 11; the eventual deployed pipeline may need a Linux container for the binwalk-heavy paths. I'll plan around this rather than try to make everything work on every OS.

**YARA rule maintenance.** The YARA ecosystem requires ongoing curation — rules go stale, families evolve, new techniques appear. I'm planning to start with a small built-in ruleset (process injection, anti-debug, crypto, persistence, network, packer signatures) and measure how well it generalizes before expanding. If the existing rules already produce a useful signal, I won't add more for the sake of it.

---

## 6. Preparation Plan

### Tools I plan to use

- **Python 3.12** as the orchestration language, with `pyzipper` for AES ZIPs, `pefile` for PE parsing, `yara-python` for rule matching, `r2pipe` for radare2 integration, `numpy` for entropy math.
- **radare2 6.1.4** for fast disassembly, function discovery, and import enumeration.
- **YARA 4.x** for pattern matching, with a starter ruleset I'll write covering the seven most common malware behaviors.
- **Ollama** running `llama3.1:8b` for natural-language explanations, locally on `localhost:11434`.
- **FastAPI** for the REST API layer, **Next.js** for the web frontend, **SQLite** for persistence. No cloud services and no external dependencies for the core analysis path.

### Lab setup

The development environment will be local on my Windows 11 machine. The architecture I'm planning is:

- `core/` — the analysis engine. Pure Python, runnable standalone for testing.
- `api/` — FastAPI service that wraps the engine, manages uploads, runs analysis as background jobs, persists results to SQLite.
- `web/` — Next.js frontend with drag-and-drop upload, results dashboard, function explorer, disassembly view, hex viewer, AI panel.
- `cli/` — Typer-based CLI for the same operations from the terminal, useful for scripting the corpus evaluation.

For Part 2's evaluation, I plan to run the pipeline as a Docker Compose stack so the experiment is reproducible by anyone reading the blog.

### Safety precautions

Specifically for this project, given the malware angle:

- **No sample execution under any circumstances.** Enforced architecturally — there is no sandbox or runtime in the codebase.
- **Samples in a `.gitignore`'d directory.** Never committed, never pushed, never shared.
- **Local AI only.** No sample data ever touches a third-party API, deliberately.
- **Read-only file access.** The pipeline opens samples for reading and never writes to them.
- **Untrusted-treated dev environment.** No banking, no email, no personal accounts logged in on the analysis machine.

### Initial hypotheses

These are the predictions I'll test in Part 2:

1. **YARA matches and entropy will dominate the verdict.** I expect single-API-category signals to turn out too noisy on real Windows binaries. My prediction: an ablation study will show YARA + entropy contribute roughly twice as much to verdict accuracy as everything else combined.
2. **Family-level clustering is achievable from imports + strings + entropy alone.** Without fuzzy hashing or machine learning, just the existing static features should be enough to put samples from the same family closer to each other than to samples from different families. I'll measure this with intra-family vs inter-family similarity scores.
3. **The AI layer adds qualitative value but should not influence the verdict score.** The verdict has to be deterministic and reproducible across runs. The AI is a presentation layer, not a decision layer. I'll enforce this architecturally by computing the verdict before the AI is ever called.

### Strategy

I'm going to follow a **measure-first, optimize-later** approach. Part 2's evaluation will tell me which heuristics are pulling weight and which are dead weight. I'll resist the urge to keep adding tools before I understand which of the existing ones are useful. If YARA matches turn out to dominate, I'll invest in the YARA rule library. If entropy dominates, I'll invest in better unpacking detection. If neither dominates and the AI layer turns out to be the main signal, that itself is a finding worth reporting.

The point of Part 1 is to set up the experiment cleanly. The point of Part 2 is to run it and report what happened — including the parts that don't work.

---

## Closing

This project is partly about building a tool and partly about putting numbers behind the intuitions experienced malware analysts use without thinking. Sikorski and Honig devote whole chapters to single techniques — XOR decoder loops, API hashing, PEB walks. Each of those is, mechanically, a few bytes of x86 followed by a recognizable pattern. If the patterns are real, they should be detectable. If they're detectable, then a thirty-second automated triage can replace the first thirty minutes of every manual analysis.

That's the bet. Part 2 will measure whether it pays off — including the cases where it doesn't.
