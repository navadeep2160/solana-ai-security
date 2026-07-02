#!/usr/bin/env python3
import subprocess
import os
import sys

# Add Solana to PATH
os.environ["PATH"] = os.path.expanduser("~/.local/share/solana/install/active_release/bin") + ":" + os.environ.get("PATH", "")

print("=== Testing cargo build-sbf ===")

# Test 1: Check if cargo sees the command
result = subprocess.run(["cargo", "--list"], capture_output=True, text=True)
if "build-sbf" in result.stdout:
    print("✅ cargo recognizes build-sbf")
else:
    print("❌ cargo does not recognize build-sbf")

# Test 2: Run cargo build-sbf as list (no shell)
print("\n=== Running: cargo build-sbf ===")
os.chdir("/tmp/solana_validator/programs/vulnerable_bank")
result = subprocess.run(["cargo", "build-sbf"], capture_output=True, text=True)
print(f"Return code: {result.returncode}")
print(f"STDOUT:\n{result.stdout[:2000]}")
print(f"STDERR:\n{result.stderr[:2000]}")

# Check for .so
print("\n=== Checking for .so ===")
for path in ["target/deploy/vulnerable_bank.so", "target/sbf-solana-solana/release/vulnerable_bank.so"]:
    if os.path.exists(path):
        print(f"✅ Found: {path} ({os.path.getsize(path):,} bytes)")
        break
else:
    print("❌ No .so found")
    print("Files in target:")
    for root, dirs, files in os.walk("target"):
        for f in files:
            if f.endswith(".so") or f.endswith(".rlib"):
                print(f"  {os.path.join(root, f)}")
