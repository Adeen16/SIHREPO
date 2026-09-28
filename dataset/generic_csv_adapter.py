import csv
import yaml
from typing import Iterator, Dict, Any

class GenericCSVAdapter:
    def __init__(self, file_path: str, map_path: str):
        self.file_path = file_path
        with open(map_path, 'r') as f:
            self.mapping = yaml.safe_load(f)

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        with open(self.file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                mapped_row = {}
                for tgt_col, src_col in self.mapping.get("columns", {}).items():
                    if src_col in row:
                        mapped_row[tgt_col] = row[src_col]
                yield mapped_row
