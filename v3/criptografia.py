from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes
from Crypto.Hash import SHA256
import random
import json
import os

ARQUIVO_CHAVES = "chaves.txt"

# Funções de criptografia e descriptografia
def criptografar_mensagem(chave, mensagem):
    cifra = AES.new(chave, AES.MODE_CBC)
    mensagem_preenchida = pad(mensagem.encode(), AES.block_size)
    mensagem_cifrada = cifra.encrypt(mensagem_preenchida)
    iv = cifra.iv
    mensagem_encriptada = iv + mensagem_cifrada
    hash_integridade = SHA256.new(mensagem_encriptada).digest()
    return mensagem_encriptada + hash_integridade

def descriptografar_mensagem(chave, mensagem_cifrada):
    iv = mensagem_cifrada[:AES.block_size]
    mensagem_cifrada_real = mensagem_cifrada[AES.block_size:-SHA256.digest_size]
    hash_integridade_recebido = mensagem_cifrada[-SHA256.digest_size:]
    hash_integridade_calculado = SHA256.new(iv + mensagem_cifrada_real).digest()
    if hash_integridade_recebido != hash_integridade_calculado:
        raise ValueError("Hash de integridade não corresponde")
    cifra = AES.new(chave, AES.MODE_CBC, iv)
    mensagem_preenchida = cifra.decrypt(mensagem_cifrada_real)
    return unpad(mensagem_preenchida, AES.block_size)

def gerar_chave_dh(primo, gerador):
    chave_privada = random.randint(1, primo - 1)
    chave_publica = pow(gerador, chave_privada, primo)
    return chave_privada, chave_publica

def calcular_chave_compartilhada(chave_privada, chave_publica, primo):
    chave_compartilhada = pow(chave_publica, chave_privada, primo)
    chave_simetrica = SHA256.new(long_to_bytes(chave_compartilhada)).digest()
    return chave_simetrica

def gerar_par_chaves_rsa(tamanho=2048):
    chave = RSA.generate(tamanho)
    chave_privada = chave.export_key()
    chave_publica = chave.publickey().export_key()
    return chave_privada, chave_publica

def salvar_chaves_criptografadas(usuario, chave_privada, chave_publica, senha, arquivo=ARQUIVO_CHAVES):
    # Hash da senha para usar como chave de criptografia
    chave = SHA256.new(senha.encode()).digest()
    cipher = AES.new(chave, AES.MODE_CBC)
    iv = cipher.iv

    # Verificar se o arquivo já existe e carregar dados existentes
    if os.path.exists(arquivo):
        with open(arquivo, "rb") as f:
            iv_existente = f.read(16)
            dados_criptografados_existente = f.read()

        cipher_existente = AES.new(chave, AES.MODE_CBC, iv_existente)
        dados_preenchidos_existente = cipher_existente.decrypt(dados_criptografados_existente)
        dados_json_existente = unpad(dados_preenchidos_existente, AES.block_size).decode()
        dados_existente = json.loads(dados_json_existente)
    else:
        dados_existente = {}

    # Adicionar novos dados
    dados_existente[usuario] = {
        "chave_privada": chave_privada.decode('utf-8'),
        "chave_publica": chave_publica.decode('utf-8')
    }

    # Criptografar os dados
    dados_json = json.dumps(dados_existente)
    dados_preenchidos = pad(dados_json.encode(), AES.block_size)
    dados_criptografados = cipher.encrypt(dados_preenchidos)

    # Salvar no arquivo
    with open(arquivo, "wb") as f:
        f.write(iv + dados_criptografados)

def carregar_chaves_criptografadas(senha, arquivo=ARQUIVO_CHAVES):
    try:
        # Hash da senha para usar como chave de criptografia
        chave = SHA256.new(senha.encode()).digest()

        # Ler dados do arquivo
        with open(arquivo, "rb") as f:
            iv = f.read(16)
            dados_criptografados = f.read()

        # Descriptografar os dados
        cipher = AES.new(chave, AES.MODE_CBC, iv)
        dados_preenchidos = cipher.decrypt(dados_criptografados)
        dados_json = unpad(dados_preenchidos, AES.block_size).decode()

        # Converter JSON para dicionário
        dados = json.loads(dados_json)
        return dados
    except (ValueError, KeyError):
        raise ValueError("Senha incorreta ou arquivo corrompido.")

def inicializar_arquivo_chaves(senha, arquivo=ARQUIVO_CHAVES):
    if not os.path.exists(arquivo):
        chave = SHA256.new(senha.encode()).digest()
        cipher = AES.new(chave, AES.MODE_CBC)
        iv = cipher.iv

        # Cria um dicionário vazio
        dados = {}

        # Criptografa os dados vazios
        dados_json = json.dumps(dados)
        dados_preenchidos = pad(dados_json.encode(), AES.block_size)
        dados_criptografados = cipher.encrypt(dados_preenchidos)

        # Salva no arquivo
        with open(arquivo, "wb") as f:
            f.write(iv + dados_criptografados)

        print(f"Arquivo de chaves inicializado em {arquivo}")
