from supports import *

def check_self_pem():
    exist_pri = os.path.exists('private.pem')
    exist_pub = os.path.exists('public.pem')
    if not exist_pri or not exist_pri:
        if input('密钥不完整，是否重新生成>>>').lower() == 'y':
            genkeys(input('请输入密码，留空为没有密码>>>'))
        else: input('你可以手动修复这个问题（按回车以继续）'); exit()