import base64
import math
from pathlib import Path

ROOT = Path(r"C:\Users\mohsen\.openclaw-autoclaw\workspace\terminus-secrets")
RELEASE = ROOT / "release"
RELEASE.mkdir(exist_ok=True)

for name in ("TerminusSecrets.apk", "TerminusSecrets.exe"):
    source = RELEASE / name
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    if name.endswith(".apk"):
        (RELEASE / f"{name}.b64").write_text(encoded, encoding="ascii")
        print(name, len(encoded), "chars")
        continue
    chunk_size = 1_500_000
    total = math.ceil(len(encoded) / chunk_size)
    for index in range(total):
        chunk = encoded[index * chunk_size : (index + 1) * chunk_size]
        (RELEASE / f"{name}.b64.part{index + 1:02d}").write_text(chunk, encoding="ascii")
    print(name, len(encoded), "chars in", total, "parts")
