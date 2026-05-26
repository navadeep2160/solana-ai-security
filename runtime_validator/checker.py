import subprocess

def validate_rust_project(path="contracts/vulnerable_bank"):
    result = subprocess.run(
        ["cargo", "check"],
        cwd=path,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("❌ INVALID RUST GENERATED")
        print(result.stderr)
        return False

    print("✅ VALID RUST CODE")
    return True