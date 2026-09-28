import hashlib
import json
import os
import pathlib

def get_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def main():
    blind_dir = pathlib.Path("NTRO-Datasets/PCAPS")
    manifest = {}
    
    if blind_dir.exists():
        for root, dirs, files in os.walk(blind_dir):
            for file in files:
                fpath = pathlib.Path(root) / file
                manifest[str(fpath.as_posix())] = get_sha256(fpath)
                
    config_dir = pathlib.Path("configs")
    config_dir.mkdir(exist_ok=True)
    with open(config_dir / "blind_manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    print("Blind manifest generated.")

if __name__ == "__main__":
    main()
