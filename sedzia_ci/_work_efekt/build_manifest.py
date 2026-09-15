#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
skip = {"MANIFEST_SHA256.json"}
files = {}
for path in sorted(root.rglob("*")):
    if path.is_file() and path.name not in skip and "__pycache__" not in path.parts and not path.name.endswith(".pyc"):
        files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
(root / "MANIFEST_SHA256.json").write_text(json.dumps({"schema":"braun.package_manifest/1","files":files}, sort_keys=True, indent=2) + "\n")
print(len(files))
