# Building Deshifro — Part 2: What I Actually Found Out

This is the second of two blog posts about Deshifro, the static malware-analysis pipeline I've been building. Part 1 was the planning post — what I intended to build, why, and what I expected to discover. This post is the results: what I actually did, what worked, what broke, what surprised me, and what I'd do differently.

If Part 1 was the experiment design, Part 2 is the lab notebook.

A small content warning before I begin: the most important finding from this project is probably embarrassing. The pipeline I built was, on its first run, confidently certain that `C:\Windows\System32\notepad.exe` was malicious. Notepad. Microsoft-signed, ships with the operating system, harmless. My tool gave it a 100% confidence MALICIOUS verdict. That false positive — and what I had to do to fix it — is the most instructive thing this project has taught me. So a fair amount of this post is about debugging my own analysis tool, which is itself a kind of reverse engineering: figuring out why a system you wrote is producing a wrong answer.

---

## Target Recap

Briefly: I'm trying to find out whether a deterministic static-analysis pipeline, built from open-source tools (radare2, YARA, custom Python heuristics, a local Llama 3.1 model for explanations), can produce verdicts on Windows PE binaries that agree with what an experienced analyst would conclude. The "deterministic" part matters — I don't want a black-box machine-learning classifier; I want a pipeline whose outputs I can explain.

The original research question was about whether the techniques I see repeated across the *Practical Malware Analysis* textbook chapters — process injection, API hashing, packers, anti-debug, embedded shellcode patterns — can be detected mechanically with sufficient accuracy and a reasonable false-positive rate.

The honest scope of what I actually got done in this post is smaller than I planned in Part 1. I did not run the full 50-malicious + 50-benign corpus evaluation, because I spent most of the available time on calibration — specifically, on figuring out *why my pipeline kept saying clean things were malicious*, and on getting the supporting infrastructure (AES ZIP extraction, AI grounding, a Cutter-style inspection UI) into a state where the corpus evaluation would even be meaningful. So this post is about that calibration work, with a smaller set of real samples than I originally planned.

That's the honest framing. What follows is what I learned along the way.

---

## Methodology

The pipeline I built has six layers, each contributing to a final verdict:

1. **File triage** — magic-byte detection (`MZ`, `\x7fELF`, `PK\x03\x04`, etc.), SHA256/MD5 hashing, architecture detection from the PE Machine field, MIME identification.
2. **String extraction** — pulling printable ASCII and UTF-16 LE strings from the binary, classifying them by category (URL, IP, registry path, API name, suspicious keyword), flagging "interesting" ones based on a curated list of malware-relevant tokens.
3. **Entropy analysis** — Shannon entropy computed in 256-byte blocks across the file, with regions labeled by entropy band (empty / normal / compressed / packed / encrypted). High-entropy regions are a packer/encryption signal.
4. **YARA rule matching** — pattern-matching against a built-in ruleset I wrote covering process injection, anti-debug, crypto, network, persistence, and packer signatures. Returns rule names with metadata including severity and MITRE technique IDs.
5. **Disassembly via radare2** — function discovery, import enumeration, cross-reference extraction, lightweight decompilation via `r2pipe`. This produces the function list that the inspect UI displays.
6. **Shellcode pattern detection** — regex scan for x86 byte sequences (GetPC `CALL/POP`, FNSTENV self-relocation, `RDTSC`, `INT 2Dh`, PEB walk via `fs:[0x30]`, XOR decoder loops, API hash resolution patterns).

A seventh, optional layer is **AI explanation via Ollama** — a local Llama 3.1 8B model takes the structured findings and produces a natural-language summary plus a draft YARA rule. This runs entirely locally so no sample data leaves the analysis machine.

The pipeline orchestrates these tools, aggregates their findings, and computes a verdict. The verdict logic is what I had to rewrite from scratch when the Notepad bug surfaced.

For inspection, I built a Cutter-style web UI on top of the analysis: a function explorer (searchable, taggable), a live disassembly view (calling radare2 on demand for any offset), and a paged hex viewer. The intent was to give the user the same view they'd get inside Cutter, but inline with the automated findings, so they don't have to context-switch between tools to verify what the pipeline is reporting.

For the workflow itself: I drove most of the analysis through the CLI (`deshifro analyze sample.exe`) for repeatability, and used the web UI for visual inspection when something needed eyeballing. The samples lived in a `tests/fixtures/` directory that's gitignored, so nothing malicious would ever get pushed to a public repository.

---

## Analysis Narrative

I want to walk through three discoveries in chronological order, because the order matters — each one led to the next.

### Discovery 1: My tool said Notepad was malicious

The first real test I ran was on `C:\Windows\System32\notepad.exe`. This was meant to be the trivial case, the smoke test, the binary that should obviously come back as CLEAN with high confidence. It is signed by Microsoft, ships with every copy of Windows, and is conceptually a text editor. There is nothing malicious about it.

The pipeline returned: **MALICIOUS, 100% confidence, 7 findings.** Among them:

```
[HIGH]    Suspicious anti_debug API usage detected
[HIGH]    Suspicious persistence API usage detected
[HIGH]    x86 pattern: getpc_call_pop
[MEDIUM]  Suspicious evasion API usage detected
[MEDIUM]  Suspicious process API usage detected
[LOW]     Suspicious registry API usage detected
[INFO]    Suspicious file API usage detected
```

This is bad. Not just slightly bad — *categorically* bad. A tool that flags Notepad as malicious is a tool you can't trust on anything.

I went through each finding to figure out why it had triggered. The story is illuminating:

- **Anti-debug**: triggered because Notepad imports `IsDebuggerPresent`. It uses this for legitimate exception handling — many Microsoft binaries do.
- **Persistence**: triggered because Notepad imports `RegSetValueExW`. It uses this to save your "Word Wrap" preference and most-recently-used file list.
- **GetPC `call_pop`**: triggered because the regex I wrote was `\xe8...\x58-\x5f` — "any 5-byte CALL followed by POP register." This pattern appears all over modern compiled code because of ASLR and position-independent code generation. It is not a shellcode-only pattern.
- **Evasion / process / registry / file**: all triggered for similar reasons. Notepad opens files (`CreateFile`), spawns the print dialog (`ShellExecute`), reads the registry, queries system time. Every Windows app does these things.

The root cause was clear: my heuristics were detecting *presence* of suspicious-category APIs, when what I needed was to detect *combinations* and *unusual usage*. Single-API-category usage is universal. Real malicious indicators come from combinations: process injection requires `VirtualAllocEx` AND `WriteProcessMemory` AND `CreateRemoteThread` together, not any one of them in isolation.

I rewrote the verdict logic with this principle:

- Single API category usage → INFO or LOW (informational only, doesn't move the verdict)
- Process injection requires 2+ injection-category APIs to flag MEDIUM
- Anti-debug requires 3+ anti-debug APIs to flag MEDIUM
- A new "Dangerous API combination" finding fires only when injection + anti-debug + network coexist
- Verdict thresholds raised from 0.70 → 0.75 for malicious
- A 40% score reduction for binaries in known-good locations (`System32`, `Program Files`)

After the rewrite, Notepad correctly verdicts as **CLEAN, 65% confidence**, with INFO-level findings noting which API categories it uses. The findings are still there for transparency — you can see Notepad imports `IsDebuggerPresent` — but they don't push the verdict.

The lesson here was about **calibration discipline**. It is very tempting, when writing a malware analyzer, to flag everything that could possibly be relevant. Every flag feels like it's "doing something." But calibration is a zero-sum game: every flag you raise on a benign binary trades against your ability to flag the malicious ones. If everything is suspicious, nothing is.

### Discovery 2: MalwareBazaar's ZIPs use AES, not ZipCrypto

The next test was a real malware sample. I downloaded SHA256 `74e9864359cb672c80b3a2c6f14dac4e68f924d28a043c9e9111b746268d2d34` from MalwareBazaar — they tag it as a known sample, password-protected with `infected`.

The pipeline received the ZIP, detected it as an archive, and tried to extract it. Result:

```
[LOW] Archive extraction failed
Extraction failed: ZIP is encrypted; tried passwords:
['infected', 'malware', 'virus', 'any.run', 'abuse.ch']
```

The first password we tried was the correct one. So why did it fail?

I went down a long debugging path before figuring this out, because the failure mode looks identical to "wrong password." Python raised `RuntimeError: Bad password` (or similar) for every attempt, including the right one. I checked the password manually with 7-Zip — it worked. So the password was definitely correct. What was happening?

The answer turns out to be a known limitation of Python's standard library: **`zipfile` only supports the legacy ZipCrypto cipher, not AES.** MalwareBazaar uses AES-256 encrypted ZIPs (the modern WinZip/7-Zip standard). When you hand an AES-encrypted ZIP to `zipfile.extractall(pwd=...)`, it doesn't tell you "this cipher isn't supported" — it tries to decrypt with ZipCrypto and produces garbage, which then fails the CRC check, which surfaces as "bad password" even though the password is right.

The fix was to switch to `pyzipper`, which supports AES-256, and to add a fallback chain: try stdlib first (fast, handles unencrypted), then `pyzipper` (handles AES), then shell out to the `7z` CLI (handles everything but slowest). The archive tool now correctly extracts MalwareBazaar samples on the first password attempt.

Once extraction worked, I could finally analyze the actual binary inside the archive. The pipeline correctly identified it as a PE32 executable, ran the full binary analyzer (strings, entropy, radare2, shellcode patterns), and produced a non-trivial finding set. I'm not going to publish the specific IOCs in this blog post — that's against MalwareBazaar's terms of use — but the verdict was SUSPICIOUS with multiple high-severity findings consistent with the family the sample is tagged as.

The dead-end here was instructive: I spent maybe two hours assuming the bug was somewhere in my password list (maybe `infected` had a typo? maybe there's a different password format?), when actually the bug was in a layer I'd assumed was correct (the `zipfile` library). The lesson is that when you're debugging an analysis pipeline, you have to be willing to question every layer, not just the one you wrote.

### Discovery 3: The AI layer hallucinates, and grounding doesn't fully fix it

Once Notepad was verdicting correctly and I could extract real samples, I started experimenting with the AI explanation layer. I'd integrated Ollama running Llama 3.1 8B locally, and exposed an "Explain this binary" button in the web UI that sent the deterministic findings to the model and asked for a natural-language summary.

The first test was on Notepad — verdict CLEAN, all findings INFO-level. The expected AI output was something like "this is a benign Windows utility that uses common system APIs." What I actually got, from the model, was:

> "This binary is a malicious version of Notepad.exe that uses various evasion and anti-debug techniques. It imports APIs related to persistence, process manipulation, and registry access, suggesting it may be designed to maintain persistence on the system."

The model had taken the INFO-level findings (which existed only to enumerate API usage, not to suggest malice) and confabulated a malicious narrative on top of them. The deterministic verdict said CLEAN, the deterministic findings were all INFO-level, and the AI took the existence of any finding at all as evidence of malice.

I rewrote the system prompt to ground the model harder:

> "You are a senior malware analyst. CRITICAL RULES: Only describe behaviors that are SUPPORTED by the evidence below. DO NOT invent findings that aren't in the data. If the verdict is 'clean' and there are few/no high-severity findings, say the binary appears benign. Common Windows APIs (CreateFile, RegSetValueEx, IsDebuggerPresent) are used by ALL apps — don't call this 'malicious' just because they're present. The verdict and confidence in the data is authoritative; align your summary with it."

After the prompt rewrite, the model produces accurate summaries on benign binaries about 80% of the time, in my informal testing. The remaining 20%, it still occasionally adds editorial flourishes that aren't strictly in the data. A larger model would help. For this project I'm accepting the limitation rather than reaching for a cloud API, because keeping inference local was a deliberate operational-security choice (see Part 1).

The interesting realization here is about **the role of an AI layer in a security tool**. I started thinking the AI summary was a presentation feature — the deterministic verdict is the truth, the AI just narrates it. But what I observed is that users will *believe the narration over the verdict*. If the deterministic verdict says CLEAN and the AI summary says "malicious version of Notepad," the user reads the prose first and absorbs the conclusion before they look at the structured findings. So the AI layer's accuracy isn't optional; it's load-bearing.

I now think the AI summary should never be allowed to contradict the deterministic verdict, and ideally should be hidden entirely on CLEAN samples unless the user explicitly asks for it. That's a UX change I'll make if this project continues.

---

## Findings

Stepping back from the three discoveries, here's what the project actually established:

**On heuristic design.** Single-feature heuristics for malware detection are nearly useless on real Windows binaries. Every legitimate application imports `CreateFile`, `RegSetValueEx`, `GetSystemTime`, and dozens of other APIs from the suspicious-categories list. The only reliable signals come from *combinations* of features — multiple injection APIs together, multiple anti-debug techniques together, or one strong feature (a YARA match, a packer signature, abnormal entropy) backed by a weaker corroborating one. The rewrite of my verdict logic to require combinations rather than presence reduced the false-positive rate on the small set of benign binaries I tested from "every binary is malicious" to "Notepad / Calculator / signed Microsoft DLLs all verdict as CLEAN."

**On infrastructure surprises.** The AES-ZIP issue was the most expensive surprise of the project. It taught me that "the password is wrong" is not always the actual problem — error messages from cryptographic libraries are rarely as specific as you want them to be. For a tool that processes samples from public repositories, you have to assume the archive format will use whatever the most recent standard is, not whatever your standard library happened to implement when it was last updated.

**On AI as a layer.** A small local LLM is good enough to *narrate* findings but not good enough to *judge* them. The natural-language summary needs to be tightly grounded in the structured data, and even then, a 20% hallucination rate is going to be visible to users. For a security tool, where false confidence is the worst failure mode, this is a non-trivial limitation.

**On the inspection UI as a learning tool.** The most pleasantly surprising part of building Deshifro was that the Cutter-style inspect view (function explorer, live disassembly, hex viewer) made me significantly faster at understanding samples myself. I expected it to be a presentation feature for users; what it actually became was the way I do most of my own checking. When the pipeline reports a finding at offset `0x1234`, I want to immediately see what's at `0x1234`, and having that one click away rather than seven (open Cutter, configure analysis, navigate to offset, decode) made me much more willing to verify findings rather than trust them.

---

## Validation

How do I know any of this is right? A few ways.

**For the Notepad verdict fix**: I can demonstrate the bug and the fix mechanically. Before the rewrite: `deshifro analyze C:\Windows\System32\notepad.exe` returned MALICIOUS (100%). After the rewrite (`compute_verdict()` now requires combinations and reduces score for known-good paths): the same command returns CLEAN (65%). The same binary, the same pipeline, only the verdict logic changed. The fix is reproducible and the regression test would be trivial to write.

**For the AES-ZIP fix**: I can demonstrate that the same MalwareBazaar sample that previously failed extraction with all five passwords now extracts successfully on the first try. The fix is the addition of `pyzipper` to the extractor fallback chain, and the fact that the password used was `infected` (the correct one) is logged in the analysis report.

**For the AI grounding**: This one's harder to validate quantitatively because I haven't built an evaluation harness yet. What I have is qualitative: a handful of test prompts on clean and malicious samples, where I compared the AI summary to the deterministic findings and counted how often the summary contradicted the verdict. Pre-grounding, contradictions were the norm. Post-grounding, they're occasional. This isn't strong validation; it's "the obvious bug is no longer obvious."

The validation I *don't* have is the corpus-scale evaluation I planned for Part 2 — the 50-malicious / 50-benign confusion matrix. I'm being honest about that. I prioritized fixing the calibration problems over running the evaluation, on the reasoning that running an evaluation against a broken pipeline would just waste samples. The eval is the obvious next step.

---

## Limitations

A list of things I know I haven't established and would need to address before claiming anything stronger than "it works on the samples I tested it on":

**No corpus-scale evaluation.** I haven't run the 50/50 confusion matrix. The accuracy claims I can make are limited to "Notepad, Calculator, and a handful of MalwareBazaar samples behaved as expected after the calibration fixes." That's anecdotal, not statistical. Until I run the full corpus, I can't claim a TPR/FPR/F1 number.

**Packed samples are still mostly opaque.** The pipeline correctly identifies packed binaries (high-entropy sections, recognized packer signatures) but cannot see past the unpacking stub. For samples packed with UPX, an `upx -d` automatic-unpack step would help. For samples packed with VMProtect or Themida, no static technique works at all — you'd need dynamic analysis.

**Custom API-hashing schemes are invisible.** My shellcode pattern detector looks for the textbook `ROR EDX, 13; ADD EDX` hash function. Real malware families increasingly use custom hash functions, which my regexes won't catch. A general "this code is computing a hash and looking it up in a table" detector would require some lightweight symbolic execution, which is out of scope for this project.

**The AI layer is qualitatively useful but not statistically validated.** I have hand-tested it on maybe twenty samples. I'd need a held-out test set with human-graded summaries to make any rigorous claim about accuracy.

**I haven't measured family-level clustering.** That was hypothesis #2 in Part 1 — that imports + strings + entropy alone are enough to cluster samples into families. I never got around to testing this because the calibration work consumed the time. The clustering experiment would need at least 30 samples per family across 4–5 families, plus a similarity metric (probably something like cosine distance over normalized feature vectors), and I haven't built any of that.

**No dynamic analysis.** This was an explicit scope decision in Part 1 — the project is static-only. But the limitation is real: a static pipeline cannot observe runtime decryption, cannot see C2 communication, cannot record syscalls, cannot detect anti-VM tricks that only fire when actually running. About a third of the samples I'd want to evaluate would be substantially more visible to a dynamic analyzer than to mine.

If I had another two weeks: run the corpus evaluation, write the family-clustering experiment, add automatic UPX unpacking, build a held-out evaluation set for the AI layer. In that order.

---

## Reflection

Three things this project taught me that I didn't expect.

**The hardest part of malware analysis is not detecting malware — it's not flagging benign things.** Coming in, I thought the difficulty would be on the malware side: outsmarting obfuscation, recognizing variants, catching novel techniques. The actual difficulty turned out to be on the benign side: writing rules that don't fire on Notepad. Every Windows binary uses `CreateFile`. Every Windows binary checks for a debugger. Every Windows binary opens registry keys. The space of "things malware does" overlaps almost completely with "things normal software does," and the malicious signal lives in the *combinations* and *frequencies* and *contexts*, not in the individual behaviors. That's a much harder problem than I appreciated when I started.

**Reading your own analysis output is a separate skill from reading malware.** When the pipeline produced its first set of findings on Notepad, I had to learn to look at that output and ask, for each finding, "is this firing because the binary is suspicious, or because my rule is too eager?" That's a different mental motion than the one you use when reading a disassembly. I think I'd have benefited from explicitly building "reading the analyzer's output" as a practice, the way you'd practice reading x86. Maybe a future iteration of this project should include a deliberate set of exercises where I run the pipeline on known-clean binaries and audit each finding for whether it's a true positive or a tool bug.

**The radare2 + Cutter-style inspection UI made me a better analyst, not just a better tool.** I expected the inspect UI (function explorer, live disassembly, hex viewer) to be a feature for users. What it actually became, partway through the project, was the way I check my own pipeline's work. When the pipeline reports something, I want to immediately verify it. Having Cutter's view inline with the automated findings — instead of having to open Cutter, configure analysis, and navigate manually — collapsed the verification loop from minutes to seconds, and I started verifying things I wouldn't have bothered to verify before. The lesson there is about feedback latency: short feedback loops are not just nice, they change what you do.

The harder-than-expected items, in order of pain:

1. **Calibration**. Roughly 60% of the project time was on getting the false-positive rate down. I knew Notepad would be hard. I didn't know it would dominate.
2. **The AES-ZIP rabbit hole**. Two hours assuming the password was wrong before I even questioned the cipher.
3. **Grounding the LLM**. Getting an 8B-parameter local model to align with a deterministic verdict turned out to require explicit, prescriptive prompts. The model's default behavior is to embellish.

The most useful techniques, in retrospect:

1. **Combination-based heuristics**. Every individual signal was too noisy on real binaries. Combinations were the only reliable thing.
2. **Treating known-good paths (`System32`, `Program Files`) as a soft prior**. A 40% score reduction for binaries in those locations corrects for the unavoidable false positives that single-binary analysis can't catch.
3. **Live disassembly via `r2pipe`**. Being able to ask "what's at offset X" from the web UI without leaving the page was the single biggest workflow improvement in the project.

If I were to do this project again, I'd start with a held-out set of ten benign Windows binaries on day one and use them to constrain my heuristics from the beginning, rather than designing the heuristics in a vacuum and discovering on day five that they flag everything. The malware-detection community has known this for decades — false-positive control is the central problem — but I had to learn it by doing.

---

## Closing

Part 1 was a bet: that the patterns the *Practical Malware Analysis* textbook teaches as universal would be detectable mechanically, and that a thirty-second automated triage could replace the first thirty minutes of manual analysis. Part 2's honest answer is "partially, with significant caveats."

The patterns are detectable. Single-feature detection is a trap. Combinations work. The infrastructure for handling real-world samples (encrypted archives, AI-grounded explanations, Cutter-style inspection) is buildable in a semester-scale project. The full statistical evaluation I wanted to run is, again honestly, two more weeks of work that this assignment didn't quite have room for.

What this project taught me, more than anything specific about malware, is that automated analysis tools are fundamentally exercises in *trust calibration*. The technical difficulty of detecting malicious patterns is real but tractable. The harder problem is ensuring that when your tool says CLEAN, you can believe it, and when it says MALICIOUS, you have evidence to back it up. Every false positive is a deposit in a credibility account that gets withdrawn the next time a real sample comes along. That insight is the thing I'm taking forward from the project, more than any specific technique.

Thanks for reading both parts. The codebase will stay public for anyone who wants to extend it; the corpus evaluation is on my list for the summer.
