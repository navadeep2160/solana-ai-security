#!/bin/bash
echo "======================================================================"
echo "  SOLANA SMART CONTRACT SECURITY PLATFORM"
echo "  Full Pipeline Execution"
echo "======================================================================"
echo ""
echo "Starting at: $(date)"
echo ""

# Step 1: Environment
echo "======================================================================"
echo "STEP 1: Environment Check"
echo "======================================================================"
echo ""
echo "--- Python ---"
python3 --version
echo ""
echo "--- Solana CLI ---"
solana --version
echo ""
echo "--- Cargo ---"
cargo --version
echo ""
read -p "Press Enter to continue..."

# Step 2: Clean
echo ""
echo "======================================================================"
echo "STEP 2: Clean Previous Runs"
echo "======================================================================"
rm -rf /tmp/solana_validator bytecode_results/675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8
echo "Cleaned."
read -p "Press Enter to continue..."

# Step 3: Run Pipeline
echo ""
echo "======================================================================"
echo "STEP 3: Execute Pipeline"
echo "======================================================================"
echo "Downloading .so → Disassembling → Pattern matching → LLM generate"
echo ""
cd ~/project/solana-ai-security
python3 -m analysis.bytecode_analyzer.test_batch --test download
read -p "Press Enter to continue..."

# Step 4: Show Generated Code
echo ""
echo "======================================================================"
echo "STEP 4: Generated Secure Rust Code"
echo "======================================================================"
echo ""
ls -la /tmp/solana_validator/programs/vulnerable_bank/src/lib.rs
echo ""
echo "--- CODE ---"
cat /tmp/solana_validator/programs/vulnerable_bank/src/lib.rs
echo ""
read -p "Press Enter to continue..."

# Step 5: Build
echo ""
echo "======================================================================"
echo "STEP 5: Build with cargo build-sbf"
echo "======================================================================"
cd /tmp/solana_validator/programs/vulnerable_bank
cargo build-sbf
read -p "Press Enter to continue..."

# Step 6: Show .so
echo ""
echo "======================================================================"
echo "STEP 6: Build Artifacts"
echo "======================================================================"
ls -la target/deploy/*.so 2>/dev/null || ls -la target/sbf-solana-solana/release/*.so
read -p "Press Enter to continue..."

# Step 7: Validator Setup
echo ""
echo "======================================================================"
echo "STEP 7: Start Local Validator"
echo "======================================================================"
echo "Open NEW terminal, run: solana-test-validator"
echo "Then return here and press Enter"
read -p "Press Enter when validator is running..."

# Step 8: Deploy
echo ""
echo "======================================================================"
echo "STEP 8: Deploy to Local Validator"
echo "======================================================================"
solana config set --url http://127.0.0.1:8899
echo ""
echo "--- Balance ---"
solana balance
echo ""
solana-keygen new -o /tmp/program-keypair.json --no-passphrase --force
PROGRAM_ID=$(solana-keygen pubkey /tmp/program-keypair.json)
echo ""
echo "Program ID: $PROGRAM_ID"
echo ""
python3 -c "
import re
with open('/tmp/solana_validator/programs/vulnerable_bank/src/lib.rs', 'r') as f:
    content = f.read()
new = re.sub(r'declare_id!\(\"[^\"]+\"\);', f'declare_id!(\"$PROGRAM_ID\");', content)
with open('/tmp/solana_validator/programs/vulnerable_bank/src/lib.rs', 'w') as f:
    f.write(new)
print('declare_id updated')
"
cd /tmp/solana_validator/programs/vulnerable_bank
cargo build-sbf
SO_FILE=$(ls target/deploy/*.so 2>/dev/null | head -1)
if [ -z "$SO_FILE" ]; then
    SO_FILE=$(ls target/sbf-solana-solana/release/*.so | head -1)
fi
echo ""
echo "Deploying: $SO_FILE"
solana program deploy --program-id /tmp/program-keypair.json "$SO_FILE"
read -p "Press Enter to continue..."

# Step 9: Verify
echo ""
echo "======================================================================"
echo "STEP 9: On-Chain Verification"
echo "======================================================================"
echo ""
echo "--- Program Show ---"
solana program show $PROGRAM_ID
echo ""
echo "--- Account Info ---"
solana account $PROGRAM_ID
read -p "Press Enter to continue..."

# Step 10: Python Test
echo ""
echo "======================================================================"
echo "STEP 10: Python Verification"
echo "======================================================================"
cat > /tmp/test_verify.py << 'PYEOF'
import urllib.request, json, sys
RPC = "http://127.0.0.1:8899"
def call(m, p=None):
    req = urllib.request.Request(RPC, data=json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p or []}).encode(), headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read())
    except Exception as e: return {"error":str(e)}
pid = sys.argv[1]
print("="*60)
print("VERIFICATION REPORT")
print("="*60)
print(f"Program: {pid}")
print(f"RPC: {RPC}")
print("="*60)
print("\n[1/3] Health:", call("getHealth").get("result","ERROR"))
print("[2/3] Slot:", call("getSlot").get("result","N/A"))
r = call("getAccountInfo",[pid,{"encoding":"jsonParsed"}])
v = r.get("result",{}).get("value")
if v:
    print("[3/3] Program: ✅ FOUND")
    print(f"   Executable: {v.get('executable')}")
    print(f"   Lamports: {v.get('lamports',0):,}")
    print(f"   Owner: {v.get('owner')}")
else:
    print("[3/3] Program: ❌ NOT FOUND")
print("="*60)
PYEOF
python3 /tmp/test_verify.py $PROGRAM_ID

# Final
echo ""
echo "======================================================================"
echo "  PIPELINE COMPLETE"
echo "======================================================================"
echo "Program ID: $PROGRAM_ID"
echo "Finished: $(date)"
echo "======================================================================"
