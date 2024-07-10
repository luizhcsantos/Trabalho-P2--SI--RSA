from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import os
import time

def gerar_nonce(tamanho=16):
    return get_random_bytes(tamanho)

def gerar_carimbo_tempo():
    return str(time.time()).encode()

def verificar_nonce_e_tempo(nonce, carimbo_tempo, limite=30):
    tempo_atual = time.time()
    tempo_recebido = float(carimbo_tempo.decode())
    if (tempo_atual - tempo_recebido) > limite:  # Verifica se a mensagem tem mais de 30 segundos
        return False
    return True

def criptografar_mensagem(chave, mensagem):
    cipher = AES.new(chave, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(mensagem, AES.block_size))
    return cipher.iv + ct_bytes

def descriptografar_mensagem(chave, mensagem):
    iv = mensagem[:16]
    ct = mensagem[16:]
    cipher = AES.new(chave, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def gerar_chave_dh(primo, gerador):
    chave_privada = int.from_bytes(get_random_bytes(32), byteorder='big')
    chave_publica = pow(gerador, chave_privada, primo)
    return chave_privada, chave_publica

def calcular_chave_compartilhada(chave_privada, chave_publica, primo):
    return pow(chave_publica, chave_privada, primo).to_bytes(32, byteorder='big')

def gerar_par_chaves_rsa():
    chave = RSA.generate(2048)
    return chave, chave.publickey()

def salvar_chaves_criptografadas(nome, chave_privada, chave_publica, senha):
    chave = SHA256.new(senha.encode()).digest()
    dados = {
        "chave_privada": chave_privada.export_key().decode(),
        "chave_publica": chave_publica.export_key().decode()
    }
    cipher = AES.new(chave, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(json.dumps(dados).encode(), AES.block_size))
    with open("chaves.txt", "wb") as f:
        f.write(cipher.iv + ct_bytes)

def carregar_chaves_criptografadas(senha):
    chave = SHA256.new(senha.encode()).digest()
    with open("chaves.txt", "rb") as f:
        iv = f.read(16)
        ct = f.read()
    cipher = AES.new(chave, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return json.loads(pt.decode())

def inicializar_arquivo_chaves(senha):
    if not os.path.exists("chaves.txt"):
        with open("chaves.txt", "wb") as f:
            salvar_chaves_criptografadas("admin", RSA.generate(2048), RSA.generate(2048).publickey(), senha)
