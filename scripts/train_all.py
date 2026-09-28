import subprocess
import sys

def run_step(name, cmd):
    print(f"\n[{name}] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"[{name}] Failed with exit code {result.returncode}")
        sys.exit(result.returncode)

def main():
    print("=== SIH145 Train All Pipeline ===")
    run_step("Manifest", [sys.executable, "scripts/generate_manifest.py"])
    run_step("Build Dataset", [sys.executable, "scripts/build_dataset.py"])
    run_step("Train Model", [sys.executable, "scripts/train_model.py"])
    run_step("Generate Docs", [sys.executable, "scripts/gen_docs.py"])
    print("\n=== Pipeline Complete ===")

if __name__ == "__main__":
    main()
