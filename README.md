# Solana AI Security Pipeline

An AI-powered pipeline that automatically detects vulnerabilities in Solana Anchor smart contracts, generates secure patches, validates compilation, deploys on a local validator, and runs fuzz tests — all in one automated loop.

---

## What It Does

1. **Static Analysis** — 6 regex detectors find missing signers, owner checks, unsafe math
2. **AST Parsing** — Extracts functions, structs, and findings with exact line numbers
3. **CFG Analysis** — Traces execution paths to find unguarded operations
4. **AI Scan** — Gemini 2.5 Flash detects semantic vulnerabilities using RAG context
5. **Patch** — Generates secure Rust fix with compiler error feedback loop
6. **Validate** — Runs `cargo check` to verify compilation
7. **Runtime** — Deploys to `solana-test-validator` and confirms on-chain
8. **Fuzz** — Sends 13 real transactions to verify exploit resistance

---

## Project Structure

```
solana-ai-security/
├── main.py                              # Pipeline orchestrator
├── agents/
│   ├── scanner/scanner_agent.py         # AI vulnerability scanner (Gemini)
│   ├── patcher/patch_agent.py           # AI secure patch generator
│   ├── validator/validator_agent.py     # cargo check validator
│   └── coordinator/workflow.py          # LangGraph state machine
├── analysis/
│   ├── static_checks/checks.py          # 6 regex-based detectors
│   └── ast_parser/
│       ├── rust_ast_parser.py           # AST parser with exact line numbers
│       └── cfg_builder.py               # Control Flow Graph analysis
├── fuzzing/
│   └── fuzzer.py                        # Real transaction fuzz engine
├── runtime_validator/
│   └── checker.py                       # solana-test-validator deploy
├── rag/
│   └── retrieval/retriever.py           # ChromaDB semantic search
├── models/
│   └── ollama_client.py                 # Gemini model loader
├── utils/
│   ├── extract_rust.py                  # Rust extractor + auto-fixer
│   ├── rust_guard.py                    # Output quality filter
│   ├── logger.py                        # Structured JSON logging
│   └── file_writer.py                   # Report + contract saver
├── contracts/
│   └── vulnerable_bank/                 # Anchor project (5 vulnerabilities)
└── outputs/
    ├── logs/                            # Per-agent timestamped logs
    ├── patched/patched_contract.rs      # Final secured contract
    └── reports/final_report.json        # Full vulnerability report
```

---

## Requirements

- Python 3.11+
- Rust + Cargo
- Anchor CLI 1.0.2
- Solana CLI 3.1+
- Google Gemini API key (free tier at https://aistudio.google.com/apikey)

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/navadeep2160/solana-ai-security.git
cd solana-ai-security
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Add your Gemini API key

```bash
echo 'GOOGLE_API_KEY=your_key_here' > .env
```

### 5. Build the contract once

```bash
cd contracts/vulnerable_bank/programs/vulnerable_bank
cargo build-sbf
cd ~/solana-ai-security
```

### 6. Set Python path

```bash
export PYTHONPATH=$PWD
export TRANSFORMERS_OFFLINE=1
```

---

## Running the Pipeline

```bash
source venv/bin/activate
export PYTHONPATH=$PWD
export TRANSFORMERS_OFFLINE=1
python main.py
```

### Expected Output

```
🚀 SOLANA AI SECURITY PIPELINE STARTED

PHASE 1: STATIC ANALYSIS
  Static findings: 5
  AST findings:    6  (with exact line numbers)
  CFG findings:    6  (execution path analysis)

PHASE 2: AI SCAN
  AI findings:     4
  Total findings:  21

PHASE 3: PATCH + VALIDATE
  ✅ cargo check passed (iteration 1)

PHASE 4: RUNTIME VALIDATION
  ✅ Deployed on local Solana validator

FINAL RESULT: { success: true, runtime_deployed: true, total_findings: 21 }
```

---

## Testing Components

Always test in this order:

```bash
python tests/test_validator.py    # cargo check must pass first
python tests/test_scanner.py      # AI scan returns JSON
python tests/test_patcher.py      # Patcher returns valid Rust
python tests/test_ast_parser.py   # AST finds exact lines
python tests/test_cfg.py          # CFG traces execution paths
python tests/test_runtime.py      # Deploy on local validator
python tests/test_fuzzer.py       # Real transaction fuzz
```

---

## Fuzz Testing

The fuzzer sends real Anchor transactions to a local validator:

```bash
python tests/test_fuzzer.py
```

Tests include: overflow (u64::MAX), underflow, zero amounts, random amounts, normal deposit/withdraw cycles. Patched contract should pass 11/13 with 2 correct rejections.

---

## Output Files

| File | Description |
|---|---|
| `outputs/patched/patched_contract.rs` | Final secured Rust contract |
| `outputs/reports/final_report.json` | Full vulnerability report |
| `outputs/logs/scanner_*.json` | AI scan logs |
| `outputs/logs/patcher_*.json` | Patch generation logs |
| `outputs/logs/validator_*.json` | Compilation logs |
| `outputs/logs/runtime_*.json` | Runtime deploy logs |
| `outputs/logs/fuzzer_*.json` | Fuzz test results |

---

## Vulnerabilities in Test Contract

The `vulnerable_bank` contract has 5 intentional vulnerabilities:

| # | Vulnerability | Location | Severity |
|---|---|---|---|
| 1 | No signer check on withdraw | Withdraw context | Critical |
| 2 | No owner verification | withdraw() | Critical |
| 3 | No signer check on close_account | CloseAccount context | Critical |
| 4 | Integer underflow | bank.balance -= amount | High |
| 5 | Integer overflow | bank.balance += amount | High |

---

## Tech Stack

| Component | Technology |
|---|---|
| AI Model | Gemini 2.5 Flash |
| Agent Framework | LangChain + LangGraph |
| Vector Database | ChromaDB |
| Embeddings | Sentence Transformers (all-MiniLM-L6-v2) |
| Smart Contract | Anchor 0.30.1 |
| Compilation check | cargo check |
| Runtime testing | solana-test-validator |
| Transaction fuzzing | solders + solana Python SDK |
| Language | Python 3.11 |

---

## Common Issues

**ModuleNotFoundError**
```bash
export PYTHONPATH=$PWD
```

**HuggingFace network error**
```bash
export TRANSFORMERS_OFFLINE=1
```

**WSL crashes during build**
Close VS Code, run in bare WSL terminal. Use `cargo check` (already configured).

**429 Rate limit**
Pipeline auto-retries after 65 seconds. Switch to `gemini-2.5-flash` if needed.

**Program ID mismatch**
```bash
cd contracts/vulnerable_bank && anchor keys sync
```

**Fuzzer validator not starting**
```bash
pkill -f solana-test-validator && sleep 5
python tests/test_fuzzer.py
```
cat > ~/solana-ai-security/README.md << 'EOF'
# Solana AI Security Pipeline

Agentic AI system for Solana smart contract and network vulnerability detection, exploitation, patching, and scoring.

---

## Week 3 Updates

### Knowledge Base (42/42 Vulnerability Coverage — 98%)

Built a persistent RAG knowledge base from 57 sources (1.5M characters):

| Collection | Chunks | Coverage |
|---|---|---|
| vulnerabilities | 167+ | 27/27 SC vulns |
| audit_findings | 66 | Fix patterns |
| architecture | 73 | Solana internals |
| network_kb | 184 | 15/15 net vulns |
| vuln_nodes | 63 | Structured nodes |

Sources include: VRust, Sealevel Attacks (11 PoCs), Neodyme, OtterSec, Trail of Bits, ACM papers, arxiv papers, CVE records, Helius reports, Anza technical reports.

### V3 KB-Driven Scanner

Zero hardcoded vulnerability rules. Flow:

### Contract → AST Facts → Dynamic KB Query → Node Matching → AI Reasoning → Findings
- Extracts structural facts from AST (no vulnerability logic in parser)
- Dynamically queries 63 vulnerability nodes based on facts
- AI confirms matches against actual code
- Detects 12-13 unique vulnerabilities per scan

### Network Vulnerability Agent

Live devnet/mainnet scanning:

### RPC Metrics → RAG Context → AI Analysis → Mitigations
Detects: Eclipse attacks, DoS spam, MEV sandwich, stake concentration, vote censorship, gossip abuse, supply chain CVEs, TPU congestion, QUIC exhaustion, validator equivocation.

### Two-Step KB-Driven Patcher

### Step 1: Contract + AST + KB → Fix Plan (what to change)
### Step 2: Fix Plan → Apply to code → Compilable Rust
No hardcoded field names or struct names — AI reads actual contract structure.

### Model Router

```python
load_model()              # Groq (fast) → Ollama fallback
load_model(force_local=True)  # qwen2.5-coder:14b (Rust patching)
```

---

## Architecture
```
Input Contract (.rs)
↓
┌─────────────────────────────────┐
│  Multi-Layer Static Analysis    │
│  - KB-driven Regex Scanner      │
│  - KB-driven AST Analyzer       │
│  - KB-driven CFG Analyzer       │
│  - V3 Node Matching Scanner     │
└──────────────┬──────────────────┘
↓
Knowledge Base (490 chunks, 63 nodes)
↓
┌─────────────────────────────────┐
│  AI Agents (Groq + Ollama)      │
│  - Scanner Agent (llama3.2:3b)  │
│  - V3 Scanner (node matching)   │
│  - Patcher (qwen2.5-coder:14b)  │
│  - Exploit Agent                │
│  - Scorer Agent                 │
│  - Network Agent                │
└──────────────┬──────────────────┘
↓
Final Report + Patched Contract
---

## Pipeline Phases

| Phase | Component | Output |
|---|---|---|
| 1 | Static Analysis (Regex+AST+CFG) | Structural findings |
| 2 | AI Scan + V3 KB Scanner | Semantic findings |
| 3 | Two-Step Patcher + Validator | Patched contract |
| 4 | Runtime Validator | Deploy verification |
| 5 | Exploit Agent | Confirmed vulnerabilities |
| 6 | Risk Scorer | CVSS-style scores |

---
```
## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set API key
echo "GROQ_API_KEY=your_key" > .env

# Run full pipeline
python3 agents/coordinator/main.py

# Run network scan
python3 agents/network/network_agent.py devnet <your_address>

# Check KB coverage
python3 -c "
from kb.kb_router import query_sc_rules
r = query_sc_rules('missing signer check', top_k=1)
print(r[0]['relevance'], r[0]['content'][:100])
"
```

---

## Vulnerability Coverage

### Smart Contracts (27/27)
Auth: Missing Signer, Missing Owner, Sysvar Spoofing, Access Control, Privilege Escalation
Account: Type Cosplay, Reinitialization, Duplicate Mutable, Closing Accounts, PDA Sharing, Bump Seed, Account Data Matching, Missing Discriminator, Account Confusion, Uninitialized
Arithmetic: Integer Overflow, Integer Underflow, Precision Loss, Unchecked Arithmetic
CPI: Arbitrary CPI, CPI Reentrancy, Missing CPI Validation
Token: Missing Token Program, SPL Token Confusion, Associated Token Misuse
Oracle: Oracle Manipulation, Flash Loan, Stale Price Data

### Network (15/15)
Eclipse Attack, Transaction Spam DoS, MEV Sandwich, Stake Concentration, Vote Censorship, Gossip Abuse, Supply Chain CVE, TPU Congestion, Slow Patch Adoption, QUIC Exhaustion, Validator Equivocation, RPC Manipulation, Leader Predictability, NFT Congestion, BPF Loader Congestion

---


# Generate Week 4 report
cat > /tmp/week4_report.py << 'SCRIPT'
report = """
╔══════════════════════════════════════════════════════════════╗
║           WEEK 4 — COMPLETE TECHNICAL REPORT                ║
║     Solana AI Security Pipeline — Agentic AI System         ║
╚══════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════
OVERVIEW
═══════════════════════════════════════════════════════════════

Week 4 transformed the pipeline from a sequential script into
a true agentic AI system with 6 new agents, zero hardcoded
rules across all parsers, and a LangGraph orchestrator.

═══════════════════════════════════════════════════════════════
DAY 1 — LANGGRAPH ORCHESTRATOR
═══════════════════════════════════════════════════════════════

Built: agents/orchestrator/graph.py

Replaced sequential coordinator (main.py) with a LangGraph
StateGraph. Each agent is a node. Decisions are edges.

Architecture:
  setup → static_analysis → ai_scan → taint → invariant
       → exploit → score → patch → validate
       → patch_verify → reflection → runtime → devnet
       → network → output → END

State: SecurityState TypedDict with 25 fields tracking
  all findings, exploit results, patch status, metrics.

Conditional routing:
  validate → patch again (if failed, max 3 iterations)
  validate → patch_verify (if compiled)

Result from Week 4 run:
  ✅ success: true
  ✅ devnet_deployed: true
  ✅ patch_iterations: 2
  📊 security_score: 75.51%
  📊 findings: 49 total

═══════════════════════════════════════════════════════════════
DAY 2 — 4 NEW AGENTS
═══════════════════════════════════════════════════════════════

1. TAINT ANALYSIS AGENT (agents/taint/taint_agent.py)
   ─────────────────────────────────────────────────
   Tracks user-controlled input flows to dangerous sinks.
   Zero hardcoded sinks or checks.

   Flow:
     AST extracts raw function code
     → KB defines what constitutes dangerous sinks
     → AI identifies unvalidated taint flows

   Result: 6 taint findings (12.2% novel discovery rate)
   Example findings:
     [high] amount parameter → bank.balance (withdraw)
     [high] new_owner parameter → bank.owner (reinitialize)
     [high] locked parameter → bank.locked (set_locked)

2. INVARIANT EXTRACTION AGENT (agents/invariant/invariant_agent.py)
   ──────────────────────────────────────────────────────────────────
   AI reads contract → extracts behavioral guarantees →
   exploit agent tests each one → broken = vulnerability.

   Result: 9 invariants extracted
   Examples:
     INV-001: balance never goes below zero [critical]
     INV-002: only owner can withdraw [high]
     INV-006: deposit never causes overflow [critical]
     INV-009: bank cannot be reinitialized if initialized [high]

3. PATCH VERIFIER AGENT (agents/verifier/patch_verifier.py)
   ──────────────────────────────────────────────────────────
   Re-runs confirmed exploits on the PATCHED contract.
   If exploit now fails → patch verified.
   If exploit still succeeds → patch incomplete.

   Result: 41/41 confirmed exploits BLOCKED (100%)
   All vulnerabilities successfully patched and verified.

4. REFLECTION AGENT (agents/reflection/reflection_agent.py)
   ──────────────────────────────────────────────────────────
   AI reads original + patched code + all findings →
   scores patch quality using KB best practices.

   Result: 7.5/10 reflection score
   - Addressed: 4 vulnerability classes
   - Missed: 1 (minor)
   - Best practice compliance: high

═══════════════════════════════════════════════════════════════
DAY 3 — STATE MACHINE ANALYSIS
═══════════════════════════════════════════════════════════════

Built: agents/state_machine/state_agent.py

Detects invalid state transition sequences.
Zero hardcoded states — AI derives them from code + KB.

Flow:
  AST extracts raw function code + state fields
  → KB provides state vulnerability patterns
  → AI builds state graph and finds invalid transitions

Result on vulnerable_bank: 4 findings
  [critical] close_account → withdraw (use-after-close)
  [critical] initialized → reinitialize (reinitialization)
  [critical] closed → deposit (deposit after close)
  [critical] closed → set_locked (state after close)

═══════════════════════════════════════════════════════════════
DAY 4 — INTERPROCEDURAL CFG
═══════════════════════════════════════════════════════════════

Built: agents/interprocedural/interprocedural_agent.py

Detects cross-function bugs missed by single-function CFG.
Zero hardcoded operators or field patterns.

Flow:
  AST extracts per-function raw code + shared state fields
  → KB defines dangerous cross-function patterns
  → AI finds state set in A but used unsafely in B

Result: 4 interprocedural findings
  [high] initialize → withdraw: owner set but not re-validated
  [high] initialize → close_account: admin set but not checked
  [high] deposit → withdraw: balance written without owner check
  [high] initialize → reinitialize: no already-initialized check

═══════════════════════════════════════════════════════════════
DAY 5 — 3 NEW VULNERABLE CONTRACTS
═══════════════════════════════════════════════════════════════

Created 3 new test contracts to validate multi-contract
scanning capability.

1. vulnerable_vault (PDA + CPI bugs)
   Vulnerabilities planted:
   - Missing PDA validation
   - Arbitrary CPI (unvalidated target_program)
   - User-supplied bump seed (not canonical)
   - Missing signer on close_vault
   Result: 22 findings detected

2. vulnerable_token (SPL token bugs)
   Vulnerabilities planted:
   - Missing token program validation
   - Type cosplay (User/Admin account confusion)
   - Missing freeze authority check
   - Duplicate mutable token accounts
   - Stale oracle price (no freshness check)
   Result: 26 findings detected

3. vulnerable_staking (governance + reinitialization)
   Vulnerabilities planted:
   - Reinitialization (no is_initialized check)
   - Governance: 1 vote = approved (no quorum)
   - Unstake without timelock or owner check
   - Flash loan: stake+vote+unstake in same tx
   - Reward precision loss (divide before multiply)
   Result: 20 findings detected

Multi-contract total: 4 contracts, 117 findings

═══════════════════════════════════════════════════════════════
DAY 6 — EVALUATION METRICS + HARDCODED RULE REMOVAL
═══════════════════════════════════════════════════════════════

EVALUATION METRICS (agents/metrics/evaluation_metrics.py):
  Total findings:       49
  Confirmed exploits:   41 (89.1% precision)
  Exploits blocked:     41/41 (100% patch verification)
  Novel findings:       6  (12.2% novel discovery rate)
  Reflection score:     7.5/10
  Multi-contract:       117 findings across 4 contracts

HARDCODED RULE REMOVAL:
  CFG builder:    Removed sensitive={withdraw,transfer,...}
                  Removed hardcoded finding types
                  Now pure fact extractor → function_facts
  AST parser:     Removed _structural_findings logic
                  Now pure fact extractor
  State machine:  Removed hardcoded keywords
  Interprocedural: Removed hardcoded operators

All detection now flows through:
  Parser (facts) → KB query → AI reasoning → Findings

═══════════════════════════════════════════════════════════════
WEEK 4 FINAL METRICS
═══════════════════════════════════════════════════════════════

Detection:
  Total findings         : 49 (vulnerable_bank)
  Layers: static=10, ast=8, cfg=9, ai=10, v3=12, taint=6
  Invariants extracted   : 9
  Novel discovery rate   : 12.2%

Exploit:
  Confirmed              : 41/46 attempted (89.1% precision)
  Blocked after patch    : 41/41 (100%)
  Patch verified         : ✅ TRUE

Quality:
  Reflection score       : 7.5/10
  Security score         : 75.51%
  Devnet deployed        : ✅ TRUE

Multi-contract:
  Contracts scanned      : 4
  Total findings         : 117
  Avg findings/contract  : 29.25

Architecture:
  Zero hardcoded rules   : ✅ (AST, CFG, State, Interproc)
  All KB+AI driven       : ✅
  LangGraph orchestrator : ✅
  New agents             : 6 (Taint, Invariant, Verifier,
                              Reflection, State Machine,
                              Interprocedural CFG)

═══════════════════════════════════════════════════════════════
COMPARISON: WEEK 3 vs WEEK 4
═══════════════════════════════════════════════════════════════

Metric                Week 3      Week 4
──────────────────────────────────────────
Agents                5           11
Findings/run          36          49
Exploit confirmed     13/27       41/46
Patch verified        No          41/41
Novel findings        0           6 (12.2%)
Invariants            0           9
State machine         No          4 findings
Interprocedural       No          4 findings
Contracts tested      1           4
Total findings        36          117
Hardcoded rules       Many        Zero
Architecture          Sequential  LangGraph
"""

print(report)

# Save to file
with open("outputs/reports/week4_report.txt", "w") as f:
    f.write(report)
print("Saved to outputs/reports/week4_report.txt")
SCRIPT

python3 /tmp/week4_report.py
