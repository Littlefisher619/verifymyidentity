如果有一天小鱼不在了，或者有其他的意外情况导致小鱼社交账户被非小鱼本人所掌控，小鱼提供了一个好办法验证正在和你聊天的是不是小鱼本人，以及说说是不是小鱼本人发的。具体来说什么时候会用到呢，举个例子——小鱼向你借钱的时候，你怀疑小鱼可能被盗号了，就可以要求小鱼提供信息验证是不是小鱼本人正在向你借钱。

记住这段RSA-2048公钥，小鱼以后不可能会更改这段数据，这是唯一可以验证小鱼身份的办法：
```
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA435fkg86neoqLUNrl1uLvFdOUuSGOvtQM2m9v2UZmK5vWncK85e0
ADPii9ylzUkS9wIaJva4MMAgyx4ES4mCnvOumk/1zOpQUk0EPgS8jjO7r1vgYlvo
y6Jk7TjUw9VXXpjqF9pO6IOIZ/M7raqBkm4C9i5NRLh/bY8JIqHCDJUyFs+mtQs1
/vdqy3DqENevy/d4xOTWaKocvotcINzZjc8js3rQELmlVts8MXWw1iHFqHidUOCi
iBAf5ijCrjCRivGu8Kw0wEuJNJ4QRSWtIK5pTB8Qzi0Ncf38DCq030i2GBLN3GzR
rCj7JOxPzpr4t/JIXrgezfIgCaRKa1mQpQIDAQAB
-----END RSA PUBLIC KEY-----
```


如何进行验证呢：
1. 小鱼对你说：你好，我是小鱼！
2. 并且将签名值发送给你：
   jq0WTHMfiQJB2ActUydzTSUhpN/xewum5eLMA0s/SN4YwNc0UfQOpoNQr7npsxMOlFWsYSy+7dWfzNJFTLNkeyEc3LK4E9b49dg4h1pe7rQEsqjvOjx7YpXU2BAmJJTcXDFUvrJrRs6Dlnnapxn9Thp4URa0Jlt9yNAy1TM56pAHl+xFswAEjpmdEATfrga579DQeNu7zQUQEjM1REDv08Oaa7xFredfeAzXe6mf0IaFWjW5zE/L9k3X/0QR3o5Zhot1V9/3hJixH/u84XN4VMQO7QObP91pzYu0VDRJLjtpOh8isPSzywcyygXdx8CEs2olaZaUT2MeTTeHNS7Qcg==
3. 这时候用公钥验证签名值是否正确，如果正确，正在和你对话的人才是小鱼
4. 把小鱼的消息存在与脚本同目录的message.txt，以UTF-8编码保存文件，然后把签名值放进signature.txt，运行脚本验签，脚本会显示结果：
```python3
# -*- coding:utf-8 -*-
import rsa, base64, traceback
pubkey_builtin = b"""-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAkuQL08keKpPs1yxaxa63zw+Q/rf5SETPFmDq3OBJSHYXhkE6gmwz
d/49QJbIJX7kphuyb6KpgYQDuT3TmxjFBjpxkcvee+S7nTtGrg8Chsu6d5O94Zxh
60Sf/vj/CbaHaHyM4OkuAQWRoRbWrpUJs29NfkVUVwLSpJqHTvI2cIOZiF+duvUS
wyC8iCXI1v222TDWbjyqmeVMd1ekCMJe2W4j2hp4zvK+I7iFc1uK+DyhWxyopdtu
/ButHxzofwRAy3ugDHZ0oBybuZTaFwN7hvUJUkYMKpJL3iD6X5vUnYHvZQDJfyE3
Qje4Ou9LPHQ17M3H4RORtvmebWp5WrXH8wIDAQAB
-----END RSA PUBLIC KEY-----"""

def generate_key(file='secret'):
    public_key, private_key = rsa.newkeys(2048)
    pub_pkcs = public_key.save_pkcs1()
    priv_pkcs = private_key.save_pkcs1()
    privkeyfile = open(file, 'wb')
    privkeyfile.write(priv_pkcs)
    privkeyfile.close()

    pubkeyfile = open(file+'_pub', 'wb')
    pubkeyfile.write(pub_pkcs)
    pubkeyfile.close()

    return pub_pkcs, priv_pkcs

def sign(privkeypath, message):
    privkeyfile = open(privkeypath, 'rb')
    privkey = privkeyfile.read()
    privkeyfile.close()
    private_key = rsa.PrivateKey.load_pkcs1(privkey)
    result = rsa.sign(message.encode('utf-8'), private_key, 'SHA-1')
    return base64.b64encode(result)

def verify(message, sign):
    public_key = rsa.PublicKey.load_pkcs1(pubkey_builtin)
    sign = base64.b64decode(sign)
    try:
        result = rsa.verify(message.encode('utf-8'), sign, public_key)
        print('验签成功')
        return True
    except rsa.pkcs1.VerificationError:
        print('验签失败：签名不正确')
        return False
    except Exception:
        traceback.print_exc()
        print('验签失败：未知错误')
        return False
if __name__ == '__main__':
    message = open('message.txt', 'r', encoding='utf-8').read().strip()
    signature = open('signature.txt', 'rb').read()
    verify(message, signature)
```
