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