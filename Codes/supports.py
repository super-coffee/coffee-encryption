# -*- coding: utf-8 -*-
from os import mkdir, listdir
from os.path import splitext
import rsa
from base64 import b64decode, b64encode
from win32 import win32clipboard
from win32.lib import win32con
from Crypto.Cipher import AES
import requests
import json
import hashlib
from random import sample


# ----------------------------------伪宏定义------------------------------------ #
prefix_m = b'-----BEGIN RSA MESSAGE-----\n'
suffix_m = b'\n-----END RSA MESSAGE-----\n'
prefix_s = b'-----BEGIN Signature-----\n'
suffix_s = b'\n-----END Signature-----\n'
prefix_f = b'-----BEGIN AES KEY-----\n'
suffix_f = b'\n-----END AES KEY-----\n'
encryption_method = 'SHA-1'
bs = AES.block_size
keytmp = 'f5nd1N0kX7ibEJy3ULsMzKCRVrogqe6v4uHt9cSWlhY8QT2xIwBFPZGapjmADOJh\
AJCz9wLNvq8DU5joeuWZxtYbsGcKXPQH1Rgpr26k7SliFady3nEOMI04BVTfmhUI'


# ---------------------------------AES Parts-------------------------------- #
def formatkey(key): # 把密码填充为 16位 的整数倍
    while len(key) % 16 != 0:
        key += '0'
    return key


def pkcs7padding(data): # 使用 pkcs7 填充数据
    padding_size = bs - len(data) % bs
    for _ in range(padding_size):
        data = data + chr(padding_size).encode()
    return data


def pkcs7unpadding(data): # 去填充
    length = len(data)
    return data[0:length - int(data[-1])]


def aes_encrypt(key, content): # 使用 AES 加密
    key_bytes = bytes(key, encoding='utf-8')
    iv = key[0:16].encode()
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    content_padding = pkcs7padding(content)
    encrypt_bytes = cipher.encrypt(content_padding)
    result = b64encode(encrypt_bytes)
    return result


def aes_decrypt(key, content): # 解密
    key_bytes = bytes(key, encoding='utf-8')
    iv = key[0:16].encode()
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypt_bytes = b64decode(content)
    decrypt_bytes = cipher.decrypt(encrypt_bytes)
    result = pkcs7unpadding(decrypt_bytes)
    return result


def changepassword(data, password):
    if len(password) > 0:
        password = formatkey(password)
        data = aes_encrypt(password, data)
    return data


# --------------------------------RSA Parts----------------------------------#
def genkeys(password, keylen=2048):
    _pubkey, _privkey = rsa.newkeys(keylen)
    if len(password) > 0:
        password = formatkey(password)
        _privkey = aes_encrypt(password, _privkey.save_pkcs1())
    else:
        _privkey = _privkey.save_pkcs1()
    return _privkey, _pubkey.save_pkcs1()


def decrypt_t(privkey, pubkey_t, text):
    third = rsa.PublicKey.load_pkcs1(pubkey_t)
    temp = text.split('\n')
    if not len(temp) > 2: return False, -1, ''

    crypto = b64decode(temp[1])
    try: message = rsa.decrypt(crypto, privkey)
    except rsa.pkcs1.DecryptionError: return False, -2, ''
    else: message = message.decode('utf-8')

    if len(temp) >= 5:
        signature = b64decode(temp[4])
        try: method_name = rsa.verify(message.encode('utf-8'), signature, third)
        except rsa.pkcs1.VerificationError: return True, 1, message
        else: return True, 0, message
    else: return True, 2, message


def encrypt_t(message, privkey, pubkey_t, need_sig):
    third = rsa.PublicKey.load_pkcs1(pubkey_t)
    ciphertext = prefix_m + b64encode(rsa.encrypt(message.encode('utf-8'), third)) + suffix_m

    if need_sig:
        signature = b64encode(rsa.sign(message.encode('utf-8'), privkey, encryption_method))
        ciphertext = ciphertext + prefix_s + signature + suffix_s

    ciphertext = ciphertext.decode()
    return True, ciphertext


def encrypt_f(path, prikey, pubkey_t): # preview
    third = rsa.PublicKey.load_pkcs1(pubkey_t)
    aes_key = ''.join(sample(keytmp, 32))
    rsaed_aes_key = prefix_f + b64encode(rsa.encrypt(aes_key.encode('utf-8'), third)) + suffix_f
    f = open(path, 'rb')
    encrypted = prefix_m + aes_encrypt(aes_key, f.read()) + suffix_m
    f.close()
    context = rsaed_aes_key + encrypted
    sha_1 = hashlib.sha1()
    sha_1.update(context)
    sig = b64encode(rsa.sign(sha_1.hexdigest().encode(), third))
    sig = prefix_s + sig + suffix_s
    context = context + sig
    return True, context


def decrypt_f(prikey, pubkey_t, data): # 犯懒暂时不想写
    data.split('\n')


# ------------------------------CoffeeKeys Parts---------------------------- #
def get_pubkey(site, mail):
    apiroot = '/api/searchKey?mail='
    try: req = requests.get(f'https://{site}/api/searchKey?mail={mail}')
    except Exception as E: return False, str(E), ''
    else: _json = req.json()['data']
    name = _json['name']
    pubkey = _json['pubkey'].replace('\r\n', '\n')
    return True, name, pubkey


# --------------------------------Config Parts------------------------------ #
def load_cfg(path):
    with open(path, 'r') as config_file:
        contents = config_file.read()
    config = json.loads(contents)
    return config


def gen_cfg(path, site, prikey):
    _json = json.dumps({
        'siteroot': site,
        'prikey': prikey
    }, indent=4)
    with open(path, 'wb') as f:
        f.write(_json.encode())


# -----------------------------------杂 项------------------------------------ #
def load_prikey(prikey, password):
    if len(password) > 0:
        password = formatkey(password)
        try: prikey = aes_decrypt(password, prikey)
        except Exception as E: return False, str(E)
    return True, rsa.PrivateKey.load_pkcs1(prikey)

def get_text():
    status = True
    win32clipboard.OpenClipboard()
    try: text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
    except Exception as E: text = str(E); status = False
    finally: win32clipboard.CloseClipboard()
    return True if status else False, text


def set_text(text):
    win32clipboard.OpenClipboard()
    win32clipboard.EmptyClipboard()
    win32clipboard.SetClipboardData(win32con.CF_OEMTEXT, text)
    win32clipboard.CloseClipboard()


def find(suffix, path='./PublicKey/'):
    filelist = list()
    try: files = listdir(path)
    except FileNotFoundError:
        mkdir(path)
        files = listdir(path)
    for filename in files:
        if splitext(filename)[1] == suffix:
            path = path + filename
            name = splitext(filename)[0]
            filelist.append({
                'name': name,
                'path': path
            })
    return filelist


# ----------------------------------Debug------------------------------------#
if __name__ == '__main__':
    pass