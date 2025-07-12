import os
import zipfile
import sys
from pathlib import Path


def is_apk(path: Path) -> bool:
    if not zipfile.is_zipfile(path):
        return False
    with zipfile.ZipFile(path) as z:
        return "AndroidManifest.xml" in z.namelist() and any(name.endswith(".dex") for name in z.namelist())


def is_xapk(path: Path) -> bool:
    if not zipfile.is_zipfile(path):
        return False
    with zipfile.ZipFile(path) as z:
        namelist = z.namelist()
        return "manifest.json" in namelist and any(name.endswith(".apk") for name in namelist)


if __name__ == "__main__":
    input_dir = "archive/apkpure-all-categories"
    xapk_cnt = 0
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith(".apk"):
                apk_path = os.path.join(root, file)
                if is_xapk(apk_path):
                    os.rename(apk_path, apk_path[:-4] + ".xapk")
                    xapk_cnt += 1
    print(f"Renamed {xapk_cnt} xapk files.")
