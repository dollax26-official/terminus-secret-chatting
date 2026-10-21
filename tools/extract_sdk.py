import os
import shutil
import zipfile

ROOT = r"C:\Users\mohsen\.openclaw-autoclaw\workspace\terminus-secrets"
SDK = os.path.join(ROOT, ".android-sdk")

JOBS = [
    ("build-tools.zip", os.path.join(SDK, "build-tools", "34.0.0")),
    ("platform-34.zip", os.path.join(SDK, "platforms", "android-34")),
    ("cmdline-tools.zip", os.path.join(SDK, "cmdline-tools", "latest")),
    ("platform-tools.zip", os.path.join(SDK, "platform-tools")),
]

for name, dest in JOBS:
    src = os.path.join(ROOT, ".downloads", name)
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(src) as archive:
        names = archive.namelist()
        prefix = names[0].split("/")[0] + "/"
        for info in archive.infolist():
            rel = info.filename[len(prefix):] if info.filename.startswith(prefix) else info.filename
            if not rel or rel.endswith("/"):
                continue
            target = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with archive.open(info) as source, open(target, "wb") as output:
                shutil.copyfileobj(source, output)
    print("extracted", name, "->", dest)
