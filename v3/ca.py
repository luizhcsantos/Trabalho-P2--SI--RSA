from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json

class CA:
    def __init__(self):
        self.chave_privada = RSA.generate(2048)
        self.chave_publica = self.chave_privada.publickey()
        self.certificados = {}

    def adicionar_certificado_cliente(self, nome_cliente, chave_publica_cliente, chave_privada_ca):
        chave_privada_ca_rsa = RSA.import_key(chave_privada_ca)
        hash_chave_publica_cliente = SHA256.new(chave_publica_cliente)
        assinatura = pkcs1_15.new(chave_privada_ca_rsa).sign(hash_chave_publica_cliente)
        certificado = {
            "chave_publica": chave_publica_cliente.decode(),
            "assinatura": assinatura.hex()
        }
        self.certificados[nome_cliente] = certificado
        self.salvar_certificados()

    def carregar_certificados(self):
        try:
            with open("certificados.json", "r") as f:
                self.certificados = json.load(f)
        except FileNotFoundError:
            self.certificados = {}
        return self.certificados

    def salvar_certificados(self):
        with open("certificados.json", "w") as f:
            json.dump(self.certificados, f, indent=4)

    def verificar_certificado(self, nome_cliente):
        certificado = self.certificados.get(nome_cliente)
        if not certificado:
            return False
        chave_publica_cliente = certificado["chave_publica"].encode()
        assinatura = bytes.fromhex(certificado["assinatura"])
        hash_chave_publica_cliente = SHA256.new(chave_publica_cliente)
        try:
            pkcs1_15.new(self.chave_publica).verify(hash_chave_publica_cliente, assinatura)
            return True
        except (ValueError, TypeError):
            return False
