from os.path import exists
from os import mkdir, system
import supports
import rsa

modes = \
'''\
[0] 解密文本        [1] 加密文本
[2] 解密文件(#PRE)  [3] 加密文件(#PRE)
[4] 更改密码        [5] 查找公钥
[6] 重载密钥列表    [7] 退出程序 

请输入模式>>>\
'''

def check_self_pem(): # 检查是否有密钥和配置文件 #MARK01
    exist_cfg = exists('Config.json')
    exist_pub = exists('public.pem')
    if not exist_pub or not exist_cfg: return False
    else: return True


def find_pubkeys(): #MARK02
    key_list = supports.find('.pem')
    key_list.insert(0, {
        'name': 'Yourself',
        'path': './public.pem'})
    return key_list


def print_pubkey(keylist, _prompt): # 打印公钥列表，并让用户选择
    for _index in range(len(keylist)):
        print(f'[{_index}] {keylist[_index]["name"]}')
    index = int(input(_prompt))
    with open(keylist[index]['path'], "rb") as f:
        third = f.read()
    return third


if __name__ == '__main__':
    prikey = None # 定义 prikey 变量，防止之后出现访问不到 #MARK00
    if not check_self_pem(): # 检测有没有密钥和配置文件 #MARK01
        print('你可以手动修复这个问题，或者重新生成密钥')
        if input('密钥不完整，是否重新生成(Y/N)>>>').lower() == 'y':
            prikey, pubkey = supports.genkeys(input('请输入密码，留空为没有密码>>>')) #MARK00
            site_root = input('请输入你的公钥服务器>>>')
            site_root = site_root if site_root else 'key.kagurazakaeri.com' # 若用户没有填公钥服务器，钦定使用演示站
            supports.gen_cfg('Config.json', site_root, prikey.decode())     # 感谢绘里姐姐提供跑演示站的服务器
            with open('public.pem', 'wb') as f:
                f.write(pubkey)
            system('cls')
        else: exit()

    if not exists('ResultFile'): mkdir('ResultFile')

    if not prikey: # 这里检测是否已加载私钥，第一次运行创建密钥后会加载私钥 #MARK00
        tmp = supports.load_cfg('Config.json')
        site_root, prikey_t = tmp['siteroot'], tmp['prikey']
        while True:
            password = input('请输入密码，若留空则没有密码>>>') # 解密私钥如果设了密码
            status, prikey = supports.load_prikey(prikey_t, password)
            if status: break
            print('密码错误')
    system('cls') # 清屏

    pubkeys = find_pubkeys() # 查找目前所有公钥，自己的放第一位 #MARK02

    while True: # 主循环，程序正式开始运行
        mode = input(modes)
        if mode == '0': # 解密
            third = print_pubkey(pubkeys, '请选择发信人 >>>')

            status, text = supports.get_text() # 尝试从剪切板读取密文
            if not status: print('剪切板中没有数据'); continue
            if not len(text.split('\n')) > 2: # 剪切板中没有期望的数据，尝试在文件中查找
                if exists('result.txt'):
                    with open('result.txt', 'r') as f:
                        text = f.read()
                else: print('没有可解密的数据'); continue # 完全没有数据可解密
            code, result = supports.decrypt_t(prikey, third, text)
            if   code == 0: print(result, '\n√ 签名有效')
            elif code == 1: print(result, '\n× 签名无效')
            elif code == 2: print(result, '\n× 没有签名')
            elif code == -1: print('无效密文')
            elif code == -2: print('无法解密，这可能不是给你的消息')

        elif mode == '1': # 加密
            third = print_pubkey(pubkeys, '请选择收信人 >>>')
            message = input('请输入信息>>>') # 得到用户要加密的信息
            need_sig = True if input('是否签名(Y/N)>>>').lower() == 'y' else False # 询问用户是否签名

            _, result = supports.encrypt_t(prikey, third, message, need_sig)
            with open('./ResultFile/result.txt', 'w') as resultfile: # 写入到文件
                resultfile.write(result)
            supports.set_text(result.encode('ascii')) # 输出至剪切板
            print('已将密文输出至 result.txt 和剪切板')

        elif mode == '2':
            third = print_pubkey(pubkeys, '请选择发信人 >>>')
            filename = input('请输入文件名>>>')

            code, msg = supports.decrypt_f(prikey, third, filename)
            if   code == 0: print(f'输出文件名为：{msg}', '\n√ 签名有效')
            elif code == 1: print(f'输出文件名为：{msg}', '\n× 签名无效')
            elif code == 2: print(f'输出文件名为：{msg}', '\n× 没有签名')
            elif code == -1: print('无效密文')
            elif code == -2: print('无法解密，这可能不是给你的消息')
            elif code == -3: print('文件损坏')

        elif mode == '3':
            third = print_pubkey(pubkeys, '请选择收信人 >>>')
            path = input('请输入文件路径>>>')
            name = input('请输入生成文件名称>>>')

            if exists(path): supports.encrypt_f(prikey, third, path, name)
            else: print('文件不存在')

        elif mode == '4': # 重置密码
            _prikey = prikey.save_pkcs1()
            _prikey = supports.changepassword(_prikey, input('请输入密码，若留空则删除密码>>>'))
            supports.gen_cfg('Config.json', site_root, _prikey.decode())

        elif mode == '5': # 从公钥服务器查找公钥
            mail = input('请输入你要找的公钥所对应的邮箱>>>')
            k_status, name, pubkey = supports.get_pubkey(site_root, mail)
            if k_status:
                with open(f'./PublicKey/{name}.pem', 'w') as f:
                    f.write(pubkey)
                find_pubkeys()
            else: print('找不到对应公钥')

        elif mode == '6': find_pubkeys() # 重载公钥列表

        elif mode == '7': exit() # 退出程序

        else: print('未知指令')

        input('按回车以重新开始') # 停住
        system('cls')