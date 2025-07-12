import gzip
import zlib
import zipfile
import magic
import base64
from io import BytesIO


def decode_text(data: bytes, encoding='utf-8'):
    try:
        return data.decode(encoding)
    except UnicodeDecodeError:
        try:
            return data.decode('latin1')
        except UnicodeDecodeError:
            return data.hex()


def decode_gzip(data: bytes):
    return gzip.decompress(data)


def decode_zlib(data: bytes):
    try:
        return zlib.decompress(data)
    except:
        return data


def decode_jar(data: bytes):
    with zipfile.ZipFile(BytesIO(data)) as jar:
        return jar.namelist()


def decode_by_mime(data: bytes, mime: str) -> str:
    try:
        if mime in {'image/jpeg', 'image/jp2', 'image/gif', 'image/x-portable-pixmap', 'image/g3fax'}:
            return f"[Image][{mime}][{data.hex()}]"
        elif mime in {'audio/mpeg', 'audio/x-hx-aac-adts', 'audio/x-mp4a-latm', 'audio/vnd.dolby.dd-raw'}:
            return f"[Audio][{mime}][{data.hex()}]"
        elif mime.startswith('text/') and mime != 'text/PGP':
            return decode_text(data)
        elif mime == 'application/x-gzip':
            return decode_gzip(data).decode('utf-8', errors='replace')
        elif mime == 'application/zlib':
            return decode_zlib(data).decode('utf-8', errors='replace')
        elif mime == 'application/java-archive':
            return f"[JAR][{mime}][{decode_jar(data)}]"
        elif mime == 'application/x-pgp-keyring' or mime == 'text/PGP':
            return f"[PGPKey][{mime}][{data.hex()}]"
        elif mime in {'application/octet-stream', 'application/x-dosexec'}:
            return f"[Binary][{mime}][{data.hex()}]"
        elif mime == 'application/x-empty':
            return f"[EmptyFile][{mime}]"
        else:
            return f"[UnsupportedMIME][{mime}][]"
    except Exception as e:
        return f"[ERRORDecoding][{mime}][{str(e)}]"
