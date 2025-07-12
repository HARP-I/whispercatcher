import zipfile
import os
if __name__ == "__main__":
    path = "archive/appchina"
    files = [os.path.join(path, f) for f in os.listdir(path) if f.endswith(".apk") or f.endswith(".xapk")]
    cnt = 0
    for file in files:
        if not zipfile.is_zipfile(file):
            print(f"{file} is not a zip file.")
            os.remove(file)
            cnt += 1
    print(f"Removed {cnt} non-apk files.")