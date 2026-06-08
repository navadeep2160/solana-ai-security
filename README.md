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

## Week 1-2 (Previous)
- Vulnerable Bank smart contract (Anchor)
- Regex-based static scanner
- Basic AST parser
- Hardcoded patcher
- Basic exploit agent
- Risk scorer

## Week 3 (Current)
- 57-source knowledge base (1.5M chars)
- 490 ChromaDB chunks across 5 collections
- 63 structured vulnerability nodes
- V3 KB-driven scanner (zero hardcoded rules)
- Two-step KB-driven patcher
- Network vulnerability agent (live RPC)
- Model router (Groq + Ollama)
- 98% vulnerability coverage (42/42)
EOF

echo "README created"