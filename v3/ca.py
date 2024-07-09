from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class CA:
    def __init__(self):
        self.chave_privada, self.certificados = self.inicializar_ca()

    def inicializar_ca(self):
        chave_privada = RSA.generate(2048)
        certificados = {}
        return chave_privada, certificados

    def adicionar_certificado_cliente(self, nome, chave_publica_cliente, chave_privada_ca):
        chave_privada_ca_rsa = RSA.import_key(chave_privada_ca)
        chave_publica_cliente_rsa = RSA.import_key(chave_publica_cliente)
        hash_chave = SHA256.new(chave_publica_cliente_rsa.export_key())
        assinatura = pkcs1_15.new(chave_privada_ca_rsa).sign(hash_chave)
        certificado = {
            "chave_publica": chave_publica_cliente_rsa.export_key().decode(),
            "assinatura": assinatura.hex()
        }
        self.certificados[nome] = certificado

    def carregar_certificados(self):
        return self.certificados
