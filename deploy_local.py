#!/usr/bin/env python3
import subprocess, os, sys, re

def run(cmd, shell=False, capture=True):
    if isinstance(cmd, str): cmd = cmd.split()
    return subprocess.run(cmd, capture_output=capture, text=True, shell=shell)

print("=" * 60)
print("Local Validator Deployment")
print("=" * 60)

# Set local
print("\n[1/7] Setting local RPC...")
run(["solana", "config", "set", "--url", "http://127.0.0.1:8899"])
print("  ✅ Local RPC: http://127.0.0.1:8899")

# Check validator
print("\n[2/7] Checking validator...")
result = run(["solana", "cluster-version"])
if result.returncode != 0:
    print("  ❌ Validator not running!")
    print("  Start in another terminal: solana-test-validator")
    sys.exit(1)
print(f"  ✅ Validator: {result.stdout.strip()}")

# Balance (free SOL on local)
print("\n[3/7] Checking balance...")
result = run(["solana", "balance"])
print(f"  {result.stdout.strip()}")

# Generate program keypair
print("\n[4/7] Generating program keypair...")
run(["solana-keygen", "new", "-o", "/tmp/program-keypair.json", "--no-passphrase", "--force"])
result = run(["solana-keygen", "pubkey", "/tmp/program-keypair.json"])
program_id = result.stdout.strip()
print(f"  Program ID: {program_id}")

# Fix declare_id!
print("\n[5/7] Updating declare_id!...")
with open("/tmp/solana_validator/programs/vulnerable_bank/src/lib.rs", 'r') as f:
    content = f.read()
new_content = re.sub(r'declare_id!\("[^"]+"\);', f'declare_id!("{program_id}");', content)
with open("/tmp/solana_validator/programs/vulnerable_bank/src/lib.rs", 'w') as f:
    f.write(new_content)
print("  ✅ Updated")

# Build
print("\n[6/7] Building program...")
os.chdir("/tmp/solana_validator/programs/vulnerable_bank")
result = run("cargo build-sbf", shell=True, capture=False)
if result.returncode != 0:
    print("  ❌ Build failed")
    sys.exit(1)
print("  ✅ Build successful")

# Deploy
print("\n[7/7] Deploying to local validator...")
so_path = "/tmp/solana_validator/programs/vulnerable_bank/target/deploy/vulnerable_bank.so"
if not os.path.exists(so_path):
    alt = "/tmp/solana_validator/programs/vulnerable_bank/target/sbf-solana-solana/release/vulnerable_bank.so"
    if os.path.exists(alt): so_path = alt

result = run(["solana", "program", "deploy", "--program-id", "/tmp/program-keypair.json", so_path], capture=False)
if result.returncode != 0:
    print("  ❌ Deploy failed")
    sys.exit(1)

print("\n" + "=" * 60)
print("✅ LOCAL DEPLOYMENT COMPLETE")
print("=" * 60)
print(f"\nProgram ID: {program_id}")
print(f"\nTest: python3 test_devnet.py {program_id} local")
print(f"Verify: solana program show {program_id}")
print("=" * 60)
