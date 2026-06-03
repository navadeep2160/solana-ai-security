import subprocess
import time
import json
import os
from pathlib import Path
from utils.logger import write_log

PROJECT_DIR = Path("contracts/vulnerable_bank")
PROGRAM_DIR = PROJECT_DIR / "programs/vulnerable_bank"

# Find the correct .so path
SO_PATHS = [
    PROGRAM_DIR / "target/deploy/vulnerable_bank.so",
    PROGRAM_DIR / "target/sbpf-solana-solana/release/vulnerable_bank.so",
]


def find_so_file() -> Path:
    for path in SO_PATHS:
        if path.exists():
            return path
    return None


class SolanaRuntimeValidator:

    def __init__(self):
        self.validator_process = None
        self.rpc_url = "http://127.0.0.1:8899"

    def start_validator(self) -> bool:
        print("[RUNTIME] Starting solana-test-validator...")
        try:
            self.validator_process = subprocess.Popen(
                ["solana-test-validator", "--reset", "--quiet"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for i in range(15):
                time.sleep(2)
                result = subprocess.run(
                    ["solana", "cluster-version", "--url", self.rpc_url],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    print(f"[RUNTIME] ✅ Validator ready (took {(i+1)*2}s)")
                    return True
            print("[RUNTIME] ❌ Validator failed to start in time")
            return False
        except Exception as e:
            print(f"[RUNTIME] ❌ Error: {e}")
            return False

    def stop_validator(self):
        if self.validator_process:
            print("[RUNTIME] Stopping validator...")
            self.validator_process.terminate()
            try:
                self.validator_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.validator_process.kill()
            self.validator_process = None

    def build_program(self) -> bool:
        print("[RUNTIME] Building program with cargo build-sbf...")
        result = subprocess.run(
            ["cargo", "build-sbf"],
            cwd=PROGRAM_DIR,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("[RUNTIME] ✅ Build successful")
            return True
        print(f"[RUNTIME] ❌ Build failed:\n{result.stderr[-500:]}")
        return False

    def deploy_program(self) -> bool:
        so_path = find_so_file()
        if not so_path:
            print("[RUNTIME] ❌ No .so file found")
            return False

        print(f"[RUNTIME] Deploying from {so_path}...")
        result = subprocess.run(
            [
                "solana", "program", "deploy",
                str(so_path),
                "--url", self.rpc_url,
                "--keypair", os.path.expanduser("~/.config/solana/id.json")
            ],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"[RUNTIME] ✅ Deployed: {result.stdout.strip()}")
            return True
        print(f"[RUNTIME] ❌ Deploy failed:\n{result.stderr[-500:]}")
        return False

    def check_balance(self) -> str:
        result = subprocess.run(
            ["solana", "balance", "--url", self.rpc_url],
            capture_output=True, text=True
        )
        return result.stdout.strip()

    def validate_runtime(self, contract_code: str) -> dict:
        output = {
            "validator_started": False,
            "build_success": False,
            "deploy_success": False,
            "balance": "",
            "so_path": str(find_so_file() or "not found"),
            "error": None
        }

        try:
            if not self.start_validator():
                output["error"] = "Validator failed to start"
                return output
            output["validator_started"] = True
            output["balance"] = self.check_balance()

            if not self.build_program():
                output["error"] = "Build failed"
                return output
            output["build_success"] = True

            if not self.deploy_program():
                output["error"] = "Deploy failed"
                return output
            output["deploy_success"] = True

            print("[RUNTIME] ✅ Contract deployed and verified on local validator")

        except Exception as e:
            output["error"] = str(e)
        finally:
            self.stop_validator()

        log_path = write_log("runtime", output)
        print(f"[RUNTIME] Log saved → {log_path}")
        return output


def run_runtime_validation(contract_code: str) -> dict:
    validator = SolanaRuntimeValidator()
    return validator.validate_runtime(contract_code)
