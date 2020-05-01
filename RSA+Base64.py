# -*- coding: utf-8 -*-
import os
import rsa
import base64
from win32 import win32clipboard
from win32.lib import win32con
from Crypto.Cipher import AES

prefix_m = b'-----BEGIN RSA + BASE64 MESSAGE-----\n'
suffix_m = b'\n-----END RSA + BASE64 MESSAGE-----\n'
prefix_s = b'-----BEGIN Signature-----\n'
suffix_s = b'\n-----END Signature-----'
encryption_method = 'SHA-1'


def formatkey(key):
    while len(key) % 16 != 0:
        key += '0'
    return (key)


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


def genkeys():
    print("正在生成密钥，请做点奇怪的事情使随机数生成器更好地生成你的密钥")
    _pubkey, _privkey = rsa.newkeys(2048)
    key = input("请输入密码，留空则没有密码>>>")
    if len(key) > 0:
        key = formatkey(key)
        _privkey = aes_encrypt(key, _privkey.save_pkcs1().decode()).encode()
    else:
        _privkey = _privkey.save_pkcs1()
    with open('private.pem', 'wb') as f:
        f.write(_privkey)
    with open('public.pem', 'wb') as f:
        f.write(_pubkey.save_pkcs1())


def changepassword(_privkey):
    key = input("请输入修改的密码，留空则删除密码>>>")
    if len(key) > 0:
        key = formatkey(key)
        _privkey = aes_encrypt(key, _privkey).encode()
    else:
        _privkey = _privkey.save_pkcs1()
    with open('private.pem', 'wb') as f:
        f.write(_privkey)


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


def findpem():
    keylist = list()
    try:
        files = os.listdir("./PublicKey/")
    except FileNotFoundError:
        os.mkdir('./PublicKey')
        files = os.listdir("./PublicKey/")
    for filename in files:
        if filename.endswith(".pem"):
            path = "./PublicKey/" + filename
            name = os.path.splitext(filename)[0]
            keylist.append({
                'name': name,
                'path': path
            })
    return keylist


def check_self_pem():  # 检查并生成
    exist_pri = os.path.exists('private.pem')
    exist_pub = os.path.exists('public.pem')
    if not exist_pri:
        print('未找到私钥')
    if not exist_pub:
        print('未找到公钥')
    if not exist_pri and not exist_pri:
        genkeys()


check_self_pem()  # 先判断是否有公钥
PublicKeyList = findpem()
PublicKeyList.insert(0, {
                'name': 'Yourself',
                'path': './public.pem'
            })

with open('private.pem', "rb") as privatefile:  # 加载自己的密钥
    p = privatefile.read()
    key = input('请输入密码，若没有请留空>>>')
    os.system('cls')
    if len(key) > 0:
        key = formatkey(key)
        p = aes_decrypt(key, p)
    if input('是否更改密码(Y/N)>>>').lower() == 'y':
        changepassword(p)
    privkey = rsa.PrivateKey.load_pkcs1(p)


while True:
    Mode = int(input("选择模式：[0] 解密, [1] 加密) >>>"))
    if Mode:

        for index in range(len(PublicKeyList)):
            print('[{index}] {name}'.format(
                index=index, name=PublicKeyList[index]['name']))
        index = int(input("请选择收信人 >>>"))
        with open(PublicKeyList[index]['path'], "rb") as thirdfile:  # 加载 别人的公钥
            p = thirdfile.read()
            third = rsa.PublicKey.load_pkcs1(p)

        message = input('Message >>>')
        ciphertext = prefix_m + base64.b64encode(rsa.encrypt(message.encode('utf-8'), third)) + suffix_m

        if input("是否签名(Y/N)>>>").lower() == "y":
            signature = base64.b64encode(rsa.sign(message.encode('utf-8'), privkey, encryption_method))
            ciphertext = ciphertext + prefix_s + signature + suffix_s

        with open('result.rsa', 'wb') as resultfile:
            resultfile.write(ciphertext)
        ciphertext = ciphertext.decode()
        set_text(ciphertext.encode('ascii'))
        print('已将密文输出至 result.rsa和剪切板')

    else:
        for index in range(len(PublicKeyList)):
            print('[{index}] {name}'.format(
                index=index, name=PublicKeyList[index]['name']))
        index = int(input("请选择发件人>>>"))
        with open(PublicKeyList[index]['path'], "rb") as thirdfile:  # 加载 别人的公钥
            p = thirdfile.read()
            third = rsa.PublicKey.load_pkcs1(p)

        text = get_text()
        temp = text.split('\n')
        if len(temp) > 2:
            c = temp
        else:
            with open('result.rsa', 'r') as resultfile:
                c = resultfile.read().split('\n')  # 按换行符分割
        crypto = base64.b64decode(c[1])  # 主体部分

        try:
            message = rsa.decrypt(crypto, privkey)
        except rsa.pkcs1.DecryptionError:
            print("无法解密，这可能不是给你的密文")
            input("回车重新开始")
            os.system('cls')
            continue
        else:
            message = message.decode('utf-8')
        if len(c) >= 5:
            signature = base64.b64decode(c[4])  # 签名部分sign 用私钥签名认证、再用公钥验证签名
            try:
                method_name = rsa.verify(
                    message.encode('utf-8'), signature, third)
            except rsa.pkcs1.VerificationError:
                print("× 签名无效")
            else:
                if method_name == encryption_method:
                    print('√ 签名有效 [%s]' % method_name)
            finally:
                print("信息为："+ message)
        else:
            print('× 没有签名')
            print("信息为："+ message)
    
    input("回车重新开始")
    os.system('cls')
