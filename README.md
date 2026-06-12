# Aegis-VM 🛡️

A lightweight, zero-dependency **Local Agentic Virtual Machine** designed to enforce strict **Cognitive-Executive Separation** for autonomous AI workflows. Aegis-VM treats all AI-generated code as inherently untrusted data inputs, intercepting and isolating operations at the runtime layer before they can touch the host operating system.

---

## 🚨 The 2026 Problem Landscape

Autonomous AI coding and execution agents traditionally execute generated scripts directly on host terminal interfaces. This architectural flaw exposes machines to devastating injection vectors and sandbox escapes. Aegis-VM is built to natively mitigate critical, real-world vulnerabilities exposed across the industry in 2026:

*   **CVE-2026-26030 (Microsoft Semantic Kernel RCE):** Mitigates the vulnerability where arbitrary code injection bypassed string-matching layers via malformed attribute lookups (`__globals__`), executing host-level commands. Aegis-VM blocks this at the structural compiler layer.
*   **CVE-2026-42434 (OpenClaw Sandbox Escape):** Prevents the specific parameter injection flaw where agents overrode target resolution routes (`host=node`) to escape the application scope. 
*   **Context Memory Degradation:** Eliminates security bypasses occurring over long runtime loops by running stateless, localized verification boundaries independent of context size.

---

## 🤝 Bilateral Strategic Alignment

Aegis-VM directly addresses the core directives established during the inaugural **India-Japan AI Strategic Dialogue held in Mumbai on April 21, 2026**. 

Operating under the **Japan-India AI Cooperation Initiative (JAI)**, this dialogue prioritized policy convergence, co-creation, and the construction of a robust, innovative, and trustworthy AI ecosystem. By delivering an entirely local, zero-cost, software-driven sandbox, Aegis-VM fulfills the bilateral push for safe, sovereign technological infrastructure—allowing regional developers to test and deploy agents locally on edge devices without relying on costly, centralized third-party cloud architectures.

---

## 🧠 Core Architecture Model

Instead of relying on heavy cloud infrastructure, Aegis-VM acts as a lightweight, zero-cost software gateway:

1. **Cognitive-Executive Separation:** The LLM agent functions entirely as a reasoning engine. It cannot generate file descriptors, allocate network sockets, or call real OS commands.
2. **Deterministic AST Compiler:** Every execution string is intercepted and disassembled into an Abstract Syntax Tree (AST) using Python's native `ast` library. Forbidden actions (such as `Import`, `exec`, `eval`, or directory path manipulation using `..`) trigger a hard-coded security breaker.
3. **Volatile Memory-Mapped FS:** The agent is given a completely simulated virtual workspace using isolated dictionary arrays inside system memory (`{}`). File operations are written and modified completely inside RAM, vanishing completely upon program termination.

---

## 💻 Zero-Cost Development & Installation Guide

Aegis-VM is engineered entirely out of Python standard libraries, requiring **zero financial expenditure** or external cloud server bills.

### Prerequisites
*   Python 3.10+
*   A free developer API key from Google AI Studio (Gemini 1.5 free tier) or a local instance of Ollama.

### Installation
```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/aegis-vm.git](https://github.com/YOUR_USERNAME/aegis-vm.git)
cd aegis-vm

# Setup your security policy configuration
mkdir config core tests
