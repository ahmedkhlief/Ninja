import os, base64, random, codecs, glob, readline, re
from Crypto import Random
import string
import core.config


def get_encryption(key, iv='0123456789ABCDEF'):
    from Crypto.Cipher import AES
    iv = os.urandom(AES.block_size)
    bkey = base64.b64decode(key)
    aes = AES.new(bkey, AES.MODE_CBC, iv)
    return aes


# Decrypt a string from base64 encoding


def decrypt(key, data):
    iv = data[0:16]
    aes = get_encryption(key, iv)
    data = aes.decrypt(base64.b64decode(data))
    return data[16:].decode("utf-8")


def decrypt_file(key, data):
    iv = data[0:16]
    aes = get_encryption(key, iv)
    data = aes.decrypt(base64.b64decode(data))
    return data[16:]  # .decode("utf-8")


# Decrypt a string from base64 encoding


def decrypt_bytes_gzip(key, data):
    iv = data[0:16]
    aes = get_encryption(key, iv)
    data = aes.decrypt(data)
    import gzip
    data = gzip.decompress(data[16:])
    try:
        data = data.decode("utf-8")
    except Exception:
        data = data
    return data


def encrypt(key, data, gzip=False):
    if gzip:
        print("Gzipping data - pre-zipped len, " + str(len(data)))
        import StringIO
        import gzip
        out = StringIO.StringIO()
        with gzip.GzipFile(fileobj=out, mode="w") as f:
            f.write(data)
        data = out.getvalue()

    # Pad with zeros
    mod = len(data) % 16
    if mod != 0:
        newlen = len(data) + (16 - mod)
        data = data.ljust(newlen, ' ')
    aes = get_encryption(key, os.urandom(16))
    data = aes.IV + aes.encrypt(data)
    if not gzip:
        data = base64.b64encode(data)
    return data


def generate_key():
    key = "".join([random.choice(string.ascii_uppercase) for i in range(32)])
    Enc = base64.b64encode(bytearray(key, "UTF-8")).decode()
    return Enc
