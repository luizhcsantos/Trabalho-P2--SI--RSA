import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256
import random

# Configurações do cliente
HOST = 'localhost'
PORT = 5000

# Gerar par de chaves Diffie-Hellman
def gerar_chave_dh(primo, gerador):
    chave_privada = random.randint(1, primo - 1)
    chave_publica = pow(gerador, chave_privada, primo)
    return chave_privada, chave_publica

# Calcular a chave compartilhada
def calcular_chave_compartilhada(chave_privada, chave_publica, primo):
    chave_compartilhada = pow(chave_publica, chave_privada, primo)
    return sha256(long_to_bytes(chave_compartilhada)).digest()[:16]

# Função para criptografar mensagens
def criptografar_mensagem(chave, mensagem):
    cifra = AES.new(chave, AES.MODE_CBC)
    mensagem_preenchida = pad(mensagem.encode(), AES.block_size)
    mensagem_cifrada = cifra.encrypt(mensagem_preenchida)
    iv = cifra.iv
    mensagem_encriptada = iv + mensagem_cifrada
    hash_integridade = sha256(mensagem_encriptada).hexdigest().encode()
    return mensagem_encriptada + hash_integridade

# Função para descriptografar mensagens
def descriptografar_mensagem(chave, mensagem_cifrada):
    iv = mensagem_cifrada[:AES.block_size]
    mensagem_cifrada_real = mensagem_cifrada[AES.block_size:-64]
    hash_integridade_recebido = mensagem_cifrada[-64:].decode()
    hash_integridade_calculado = sha256(iv + mensagem_cifrada_real).hexdigest()
    if hash_integridade_recebido != hash_integridade_calculado:
        raise ValueError("Hash de integridade não corresponde")
    cifra = AES.new(chave, AES.MODE_CBC, iv)
    mensagem_preenchida = cifra.decrypt(mensagem_cifrada_real)
    return unpad(mensagem_preenchida, AES.block_size).decode()

# Função para receber mensagens do servidor
def receber_mensagens(socket_cliente, chave_compartilhada):
    while True:
        try:
            resposta_encriptada = socket_cliente.recv(2048)
            if not resposta_encriptada:
                break
            resposta = descriptografar_mensagem(chave_compartilhada, resposta_encriptada)
            print(f'Servidor: {resposta}')
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
chave_privada, chave_publica = gerar_chave_dh(primo, gerador)
socket_cliente.sendall(f'{chave_publica}'.encode())
chave_publica_servidor = int(socket_cliente.recv(1024).decode())
chave_compartilhada = calcular_chave_compartilhada(chave_privada, chave_publica_servidor, primo)
print('Chave compartilhada estabelecida:', chave_compartilhada.hex())

# Enviar nome do cliente
nome_cliente = input('Digite seu nome: ')
mensagem_encriptada = criptografar_mensagem(chave_compartilhada, nome_cliente)
socket_cliente.sendall(mensagem_encriptada)

# Iniciar thread para receber mensagens do servidor
thread_receber = threading.Thread(target=receber_mensagens, args=(socket_cliente, chave_compartilhada))
thread_receber.start()

# Enviar mensagens para o servidor
try:
    while True:
        destinatario = input('Para: ')
        mensagem = input('Mensagem: ')
        mensagem_enviar = f'{destinatario}:{mensagem}'
        mensagem_encriptada = criptografar_mensagem(chave_compartilhada, mensagem_enviar)
        socket_cliente.sendall(mensagem_encriptada)
except Exception as e:
    print(f'Erro: {e}')
finally:
    socket_cliente.close()
