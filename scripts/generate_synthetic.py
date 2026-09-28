"""
scripts/generate_synthetic.py
------------------------------
CLI wrapper for synthetic PCAP generation.
Delegates to datasets_gen.generate.main().

Usage:
    python -m scripts.generate_synthetic [--out datasets/synthetic/] [--seed 1337]
"""
from datasets_gen.generate import main

if __name__ == "__main__":
    main()
