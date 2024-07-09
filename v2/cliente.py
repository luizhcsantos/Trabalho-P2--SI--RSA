import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes
from Crypto.Hash import SHA256
import random
import json

# Configurações do cliente
HOST = 'localhost'
PORT = 5000

# Função para gerar chave privada e pública Diffie-Hellman
def gerar_chave_dh(primo, gerador):
    chave_privada = random.randint(1, primo - 1)
    chave_publica = pow(gerador, chave_privada, primo)
    return chave_privada, chave_publica

# Função para calcular chave compartilhada
def calcular_chave_compartilhada(chave_privada, chave_publica, primo):
    chave_compartilhada = pow(chave_publica, chave_privada, primo)
    chave_simetrica = SHA256.new(long_to_bytes(chave_compartilhada)).digest()
    return chave_simetrica

# Função para gerar par de chaves RSA
def gerar_par_chaves_rsa(tamanho=2048):
    chave = RSA.generate(tamanho)
    chave_privada = chave.export_key()
    chave_publica = chave.publickey().export_key()
    return chave_privada, chave_publica

# Função para criptografar mensagens
def criptografar_mensagem(chave, mensagem):
    cifra = AES.new(chave, AES.MODE_CBC)
    mensagem_preenchida = pad(mensagem.encode(), AES.block_size)
    mensagem_cifrada = cifra.encrypt(mensagem_preenchida)
    iv = cifra.iv
    mensagem_encriptada = iv + mensagem_cifrada
    hash_integridade = SHA256.new(mensagem_encriptada).digest()
    return mensagem_encriptada + hash_integridade

# Função para descriptografar mensagens
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

# Função para receber mensagens do servidor
def receber_mensagens(socket_cliente, chave_simetrica):
    while True:
        try:
            resposta_encriptada = socket_cliente.recv(2048)
            if not resposta_encriptada:
                break
            resposta = descriptografar_mensagem(chave_simetrica, resposta_encriptada).decode()
            print(f'\rMensagem recebida>> {resposta}\nPara: ', end='')
        except Exception as e:
            print(f'Erro ao receber mensagem: {e}')
            break

# Configurar socket do cliente
socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_cliente.connect((HOST, PORT))

# Receber os parâmetros primo e gerador do servidor
parametros = socket_cliente.recv(1024).decode().split(',')
primo = int(parametros[0])
gerador = int(parametros[1])

# Gerar par de chaves Diffie-Hellman
chave_privada_dh, chave_publica_dh = gerar_chave_dh(primo, gerador)
socket_cliente.sendall(f'{chave_publica_dh}'.encode())
chave_publica_servidor_dh = int(socket_cliente.recv(1024).decode())
chave_simetrica = calcular_chave_compartilhada(chave_privada_dh, chave_publica_servidor_dh, primo)
print('Chave simétrica estabelecida:', chave_simetrica.hex())

# Gerar par de chaves RSA
chave_privada_rsa, chave_publica_rsa = gerar_par_chaves_rsa()
print('Par de chaves RSA gerado.')

# Enviar nome do cliente e chave pública RSA criptografada
nome_cliente = input('Digite seu nome: ')
dados = f'{nome_cliente}'
dados_criptografados = criptografar_mensagem(chave_simetrica, dados)
socket_cliente.sendall(dados_criptografados)
socket_cliente.sendall(chave_publica_rsa)

# Receber o certificado assinado pela CA
certificado = json.loads(socket_cliente.recv(4096).decode())
# print(f"Certificado recebido: {certificado}")

# Iniciar thread para receber mensagens do servidor
thread_receber = threading.Thread(target=receber_mensagens, args=(socket_cliente, chave_simetrica))
thread_receber.start()

# Enviar mensagens para o servidor
try:
    while True:
        destinatario = input('Mensagem para: ')
        mensagem = input('Digite a mensagem: ')
        mensagem_enviar = f'{destinatario}:{mensagem}'
        mensagem_encriptada = criptografar_mensagem(chave_simetrica, mensagem_enviar)
        socket_cliente.sendall(mensagem_encriptada)
except Exception as e:
    print(f'Erro: {e}')
finally:
    socket_cliente.close()
