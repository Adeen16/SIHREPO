import sys
import subprocess
import os
import importlib

def check_command(cmd, name):
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0].strip() if result.stdout else "Available"
            print(f"[OK] {name} is available. ({version_line})")
        else:
            print(f"[WARN] {name} check returned non-zero. Might not be fully available.")
    except Exception as e:
        print(f"[FAIL] {name} is NOT available or failed to execute. Error: {e}")

def check_import(module_name, pip_name=None):
    try:
        importlib.import_module(module_name)
        print(f"[OK] Python module '{pip_name or module_name}' imported successfully.")
    except Exception as e:
        print(f"[FAIL] Python module '{pip_name or module_name}' failed to import: {e}")

def main():
    print("========================================")
    print("Environment Validation Report")
    print("========================================")

    # 1. Python version
    print(f"[INFO] Python Version: {sys.version.split()[0]}")

    # 2. Required Python imports
    print("\n--- Checking Python Dependencies ---")
    dependencies = [
        ("numpy", "numpy"),
        ("pandas", "pandas"),
        ("scapy", "scapy"),
        ("pyshark", "pyshark"),
        ("sklearn", "scikit-learn"),
        ("xgboost", "xgboost"),
        ("joblib", "joblib"),
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("websockets", "websockets"),
        ("pydantic", "pydantic"),
        ("dotenv", "python-dotenv"),
        ("pytest", "pytest"),
        ("requests", "requests")
    ]
    for mod_name, pip_name in dependencies:
        check_import(mod_name, pip_name)

    # 3. Node & NPM
    print("\n--- Checking Node.js & NPM ---")
    check_command("node --version", "Node.js")
    check_command("npm --version", "npm")

    # 4. Git
    print("\n--- Checking Git ---")
    check_command("git --version", "Git")

    # 5. Wireshark & Npcap
    print("\n--- Checking Network Tools ---")
    wireshark_path = r"C:\Program Files\Wireshark\Wireshark.exe"
    if os.path.exists(wireshark_path):
        print("[OK] Wireshark is available.")
    else:
        print("[FAIL] Wireshark is NOT available.")

    npcap_path1 = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32", "Npcap")
    npcap_path2 = r"C:\Program Files\Npcap"
    if os.path.exists(npcap_path1) or os.path.exists(npcap_path2):
        print("[OK] Npcap is available.")
    else:
        print("[FAIL] Npcap is NOT available.")

    print("\n========================================")

if __name__ == "__main__":
    main()
