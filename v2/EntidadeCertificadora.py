from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json
import os

ARQUIVO_CERTIFICADOS = "certificados.txt"
ARQUIVO_CHAVE_CA = "chave_ca.pem"

# Função para gerar par de chaves RSA
def gerar_par_chaves_rsa(tamanho=2048):
    chave = RSA.generate(tamanho)
    chave_privada = chave.export_key()
    chave_publica = chave.publickey().export_key()
    return chave_privada, chave_publica

# Gerar par de chaves da CA
def gerar_chaves_ca():
    chave_privada_ca, chave_publica_ca = gerar_par_chaves_rsa()
    with open(ARQUIVO_CHAVE_CA, 'wb') as f:
        f.write(chave_privada_ca)
    return chave_privada_ca, chave_publica_ca

# Carregar chave privada da CA
def carregar_chave_privada_ca():
    if os.path.exists(ARQUIVO_CHAVE_CA):
        with open(ARQUIVO_CHAVE_CA, 'rb') as f:
            chave_privada_ca = RSA.import_key(f.read())
        return chave_privada_ca
    else:
        return None

# Assinar chave pública do cliente com a chave privada da CA
def assinar_chave_publica(chave_publica_cliente, chave_privada_ca):
    hash_chave_publica = SHA256.new(chave_publica_cliente)
    assinatura = pkcs1_15.new(chave_privada_ca).sign(hash_chave_publica)
    return assinatura

# Salvar certificados em um arquivo TXT
def salvar_certificados(certificados):
    with open(ARQUIVO_CERTIFICADOS, 'w') as f:
        json.dump(certificados, f, indent=4)

# Carregar certificados de um arquivo TXT
def carregar_certificados():
    if os.path.exists(ARQUIVO_CERTIFICADOS):
        with open(ARQUIVO_CERTIFICADOS, 'r') as f:
            certificados = json.load(f)
        return certificados
    else:
        return {}

# Inicialização da CA
def inicializar_ca():
    chave_privada_ca = carregar_chave_privada_ca()
    if chave_privada_ca is None:
        chave_privada_ca, chave_publica_ca = gerar_chaves_ca()
        print("Chaves da CA geradas.")
    else:
        print("Chaves da CA carregadas.")
    certificados = carregar_certificados()
    return chave_privada_ca, certificados

# Adicionar certificado ao cliente
def adicionar_certificado_cliente(nome_cliente, chave_publica_cliente, chave_privada_ca):
    certificados = carregar_certificados()
    assinatura = assinar_chave_publica(chave_publica_cliente, chave_privada_ca)
    certificados[nome_cliente] = {
        "chave_publica": chave_publica_cliente.decode('utf-8'),
        "assinatura": assinatura.hex()
    }
    salvar_certificados(certificados)

# Teste de inicialização da CA
if __name__ == "__main__":
    chave_privada_ca, certificados = inicializar_ca()
    print("CA inicializada.")
    print("Certificados:", certificados)
