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


# ----------------------------------伪宏定义------------------------------------ #
prefix_m = b'-----BEGIN RSA MESSAGE-----\n'
suffix_m = b'\n-----END RSA MESSAGE-----\n'
prefix_s = b'-----BEGIN Signature-----\n'
suffix_s = b'\n-----END Signature-----'
encryption_method = 'SHA-1'


# ---------------------------------AES Parts-------------------------------- #
def formatkey(key): # 把密码填充为 16位 的整数倍
    while len(key) % 16 != 0:
        key += '0'
    return key


def pkcs7padding(text): # 使用 pkcs7 填充数据
    bs = AES.block_size
    length = len(text)
    bytes_length = len(bytes(text, encoding='utf-8'))
    padding_size = length if(bytes_length == length) else bytes_length
    padding = bs - padding_size % bs
    padding_text = chr(padding) * padding
    return text + padding_text


def pkcs7unpadding(text): # 去填充
    length = len(text)
    unpadding = ord(text[length-1])
    return text[0:length-unpadding]


def aes_encrypt(key, content): # 使用 AES 加密
    key_bytes = bytes(key, encoding='utf-8')
    iv = key[0:16].encode()
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    content_padding = pkcs7padding(content)
    encrypt_bytes = cipher.encrypt(bytes(content_padding, encoding='utf-8'))
    result = str(b64encode(encrypt_bytes), encoding='utf-8')
    return result


def aes_decrypt(key, content): # 解密
    key_bytes = bytes(key, encoding='utf-8')
    iv = key[0:16].encode()
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypt_bytes = b64decode(content)
    decrypt_bytes = cipher.decrypt(encrypt_bytes)
    result = str(decrypt_bytes, encoding='utf-8')
    result = pkcs7unpadding(result)
    return result


def changepassword(data, password):
    if len(password) > 0:
        password = formatkey(password)
        data = aes_encrypt(password, data)
    return data.encode()


# --------------------------------RSA Parts----------------------------------#
def genkeys(password, keylen=2048):
    _pubkey, _privkey = rsa.newkeys(keylen)
    if len(password) > 0:
        password = formatkey(password)
        _privkey = aes_encrypt(password, _privkey.save_pkcs1().decode()).encode()
    else:
        _privkey = _privkey.save_pkcs1()
    return _privkey, _pubkey.save_pkcs1()


def decrypt(privkey, pubkey_t, text):
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


def encrypt(message, privkey, pubkey_t, need_sig):
    third = rsa.PublicKey.load_pkcs1(pubkey_t)
    ciphertext = prefix_m + b64encode(rsa.encrypt(message.encode('utf-8'), third)) + suffix_m

    if need_sig:
        signature = b64encode(rsa.sign(message.encode('utf-8'), privkey, encryption_method))
        ciphertext = ciphertext + prefix_s + signature + suffix_s

    ciphertext = ciphertext.decode()
    return True, ciphertext


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