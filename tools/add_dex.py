import shutil
import sys
import zipfile

if len(sys.argv) != 4:
    raise SystemExit("usage: add_dex.py <unsigned.apk> <classes.dex> <output.apk>")

source, dex, output = sys.argv[1:4]
shutil.copyfile(source, output)
with zipfile.ZipFile(output, "a", zipfile.ZIP_DEFLATED) as archive:
    archive.write(dex, "classes.dex")
print("added classes.dex ->", output)
