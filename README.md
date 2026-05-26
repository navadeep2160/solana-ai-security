# Solana AI Security Pipeline

An AI-powered pipeline that automatically detects vulnerabilities in Solana Anchor smart contracts, generates secure patches, and validates the fix compiles — all in one automated loop.

---

## What It Does

1. **Scans** your Solana contract for vulnerabilities using Gemini AI + RAG knowledge base
2. **Patches** the vulnerable code automatically
3. **Validates** the patched contract compiles with `cargo check`
4. **Retries** up to 3 times using compiler errors as feedback if it fails

---

## Requirements

- Python 3.11+
- Rust + Cargo
- Anchor CLI 1.0.2
- Solana CLI
- Google Gemini API key

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

Create a `.env` file in the root:
Get a free key at: https://aistudio.google.com/apikey

### 5. Build the contract once

```bash
cd contracts/vulnerable_bank
anchor keys sync
cd programs/vulnerable_bank
cargo build-sbf
cd ~/solana-ai-security
```

---

## Run the Pipeline

```bash
source venv/bin/activate
export PYTHONPATH=$PWD
python main.py
```

---

## Test Individual Components

Always test in this order before running the full pipeline:

```bash
python tests/test_validator.py
python tests/test_scanner.py
python tests/test_patcher.py
```

---

## Output Files

| File | Description |
|---|---|
| `outputs/patched/patched_contract.rs` | Final secured contract |
| `outputs/reports/final_report.json` | Vulnerability report |
| `outputs/logs/` | Per-agent run logs |

---

## Common Issues

**ModuleNotFoundError**
```bash
export PYTHONPATH=$PWD
```

**WSL crashes during build**
Close VS Code, run in bare WSL terminal, or use `cargo check` (already configured).

**429 Rate limit**
Pipeline auto-retries after 65 seconds.

**Program ID mismatch**
```bash
cd contracts/vulnerable_bank && anchor keys sync
```

---

## Tech Stack

| Component | Technology |
|---|---|
| AI Model | Gemini 2.5 Flash |
| Agent Framework | LangChain + LangGraph |
| Vector Database | ChromaDB |
| Smart Contract | Anchor 0.30.1 |
| Validation | cargo check |
| Language | Python 3.11 |
