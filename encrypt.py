#!/usr/bin/env python3
"""Шифрует страницу паролем (PBKDF2-SHA256 + AES-256-CBC) и заворачивает в gate.html.
Запуск: python3 encrypt.py <вход.html> <выход.html> "<пароль>" "<заголовок>" "<подзаголовок>" "<имя ярлыка>"
"""
import base64, hashlib, os, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
ITER = 20000
MARK = b'DERZAI1\n'


def encrypt(src, dst, password, title, subtitle, apptitle):
    html = open(src, 'rb').read()
    salt, iv = os.urandom(16), os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITER, 32)
    data = MARK + html
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    b64 = base64.b64encode(ct).decode()
    b64 = '\n'.join(b64[i:i + 120] for i in range(0, len(b64), 120))
    gate = open(os.path.join(HERE, 'gate.html'), encoding='utf-8').read()
    aes = open(os.path.join(HERE, '.tools', 'aes-js.min.js'), encoding='utf-8').read()
    crypto = open(os.path.join(HERE, 'gate-crypto.js'), encoding='utf-8').read()
    for k, v in [('__AESJS__', aes), ('__CRYPTO__', crypto), ('__SALT__', base64.b64encode(salt).decode()),
                 ('__IV__', base64.b64encode(iv).decode()), ('__ITER__', str(ITER)), ('__CT__', b64),
                 ('__TITLE__', title), ('__SUBTITLE__', subtitle), ('__APPTITLE__', apptitle)]:
        gate = gate.replace(k, v)
    open(dst, 'w', encoding='utf-8').write(gate)
    print('%s: %d КБ (ключ %s…)' % (os.path.basename(dst), len(gate.encode()) // 1024, key.hex()[:8]))
    return key.hex()


if __name__ == '__main__':
    encrypt(*sys.argv[1:7])
