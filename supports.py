# -*- coding: utf-8 -*-
import os
import rsa
import base64
from win32 import win32clipboard
from win32.lib import win32con
from Crypto.Cipher import AES


# ----------------------------------伪宏定义------------------------------------ #
prefix_m = b'-----BEGIN RSA + BASE64 MESSAGE-----\n'
suffix_m = b'\n-----END RSA + BASE64 MESSAGE-----\n'
prefix_s = b'-----BEGIN Signature-----\n'
suffix_s = b'\n-----END Signature-----'
encryption_method = 'SHA-1'
modes = \
'''
[0] 解密
[1] 加密
[2] 更改密码
[3] 重载密钥列表
'''


# ---------------------------------AES Parts-------------------------------- #
def formatkey(key):
    while len(key) % 16 != 0:
        key += '0'
    return key


def pkcs7padding(text):
    bs = AES.block_size
    length = len(text)
    bytes_length = len(bytes(text, encoding='utf-8'))
    padding_size = length if(bytes_length == length) else bytes_length
    padding = bs - padding_size % bs
    padding_text = chr(padding) * padding
    return text + padding_text


def pkcs7unpadding(text):
    length = len(text)
    unpadding = ord(text[length-1])
    return text[0:length-unpadding]


def aes_encrypt(key, content):
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    content_padding = pkcs7padding(content)
    encrypt_bytes = cipher.encrypt(bytes(content_padding, encoding='utf-8'))
    result = str(base64.b64encode(encrypt_bytes), encoding='utf-8')
    return result


def aes_decrypt(key, content):
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypt_bytes = base64.b64decode(content)
    decrypt_bytes = cipher.decrypt(encrypt_bytes)
    result = str(decrypt_bytes, encoding='utf-8')
    result = pkcs7unpadding(result)
    return result


def changepassword(data, password):
    if len(password) > 0:
        password = formatkey(password)
        data = aes_encrypt(password, data).encode()
    else:
        data = data.encode()
    return data


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

    crypto = base64.b64decode(temp[1])
    try: message = rsa.decrypt(crypto, privkey)
    except rsa.pkcs1.DecryptionError: return False, -2, ''
    else: message = message.decode('utf-8')

    if len(temp) >= 5:
        signature = base64.b64decode(temp[4])
        try: method_name = rsa.verify(message.encode('utf-8'), signature, third)
        except rsa.pkcs1.VerificationError: return True, 1, message
        else:
            if method_name == encryption_method: return True, 0, message
            else: return True, 2, message
    else: return True, 3, message


def encrypt(message, privkey, pubkey_t, need_sig):
    third = rsa.PublicKey.load_pkcs1(pubkey_t)
    ciphertext = prefix_m + base64.b64encode(rsa.encrypt(message.encode('utf-8'), third)) + suffix_m

    if need_sig:
        signature = base64.b64encode(rsa.sign(message.encode('utf-8'), privkey, encryption_method))
        ciphertext = ciphertext + prefix_s + signature + suffix_s

    ciphertext = ciphertext.decode()
    return True, ciphertext


# -----------------------------------杂 项------------------------------------ #
def load_prikey(path, password):
    with open(path, "rb") as privatefile:
        p = privatefile.read()
    if len(password) > 0:
        key = formatkey(key)
        try:
            p = aes_decrypt(key, p)
            return True, rsa.PrivateKey.load_pkcs1(p)
        except Exception as E:
            return False, str(E)

def get_text():
    win32clipboard.OpenClipboard()
    text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
    win32clipboard.CloseClipboard()
    return text


def set_text(text):
    win32clipboard.OpenClipboard()
    win32clipboard.EmptyClipboard()
    win32clipboard.SetClipboardData(win32con.CF_OEMTEXT, text)
    win32clipboard.CloseClipboard()


def find(suffix, path='./PublicKey/'):
    filelist = list()
    try: files = os.listdir(path)
    except FileNotFoundError:
        os.mkdir(path)
        files = os.listdir(path)
    for filename in files:
        if filename.endswith(suffix):
            path = path + filename
            name = os.path.splitext(filename)[0]
            filelist.append({
                'name': name,
                'path': path
            })
    return filelist


# ----------------------------------Debug------------------------------------#
if __name__ == '__main__':
    import requests
    siteroot = 'key.kagurazakaeri.com'
    apiroot = '/api/searchKey?mail='
    mail = 'charlieyu4994@outlook.com'
    req = requests.get(f'https://{siteroot}/api/searchKey?mail={mail}')
    _json = req.json()['data']
    name = _json['name']
    pubkey = _json['pubkey'].replace('\r\n', '\n')
    print([pubkey])
    with open(f'{name}.pem', 'w') as f:
        f.write(pubkey)
    pass