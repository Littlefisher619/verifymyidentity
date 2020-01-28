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
