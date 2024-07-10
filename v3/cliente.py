import socket
import threading
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes
from Crypto.Hash import SHA256
import random
import json
from criptografia import (
    criptografar_mensagem, descriptografar_mensagem,
    gerar_chave_dh, calcular_chave_compartilhada,
    gerar_par_chaves_rsa, gerar_nonce, gerar_carimbo_tempo
)

# Configurações do cliente
HOST = 'localhost'
PORT = 5000

# Função para receber mensagens do servidor
def receber_mensagens(socket_cliente, chave_simetrica):
    while True:
        try:
            resposta_encriptada = socket_cliente.recv(2048)
            if not resposta_encriptada:
                break
            resposta = descriptografar_mensagem(chave_simetrica, resposta_encriptada).decode()
            print(f'\rMensagem recebida: {resposta}\nPara: ', end='')
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
# Remover ou comentar a linha abaixo para não imprimir a chave simétrica
# print('Chave simétrica estabelecida:', chave_simetrica.hex())

# Gerar par de chaves RSA
chave_privada_rsa = RSA.generate(2048)
chave_publica_rsa = chave_privada_rsa.publickey()
print('Par de chaves RSA gerado.')

# Enviar nome do cliente, chave pública RSA criptografada, nonce e carimbo de tempo
nome_cliente = input('Digite seu nome: ')
nonce = gerar_nonce()
carimbo_tempo = gerar_carimbo_tempo()
dados = f'{nome_cliente},{nonce.hex()},{carimbo_tempo.decode()}'
dados_criptografados = criptografar_mensagem(chave_simetrica, dados.encode())
socket_cliente.sendall(dados_criptografados)
socket_cliente.sendall(chave_publica_rsa.export_key())

# Receber o certificado assinado pela CA
certificado = json.loads(socket_cliente.recv(4096).decode())
print(f"Certificado recebido: {certificado}")

# Iniciar thread para receber mensagens do servidor
thread_receber = threading.Thread(target=receber_mensagens, args=(socket_cliente, chave_simetrica))
thread_receber.start()

# Enviar mensagens para o servidor
try:
    while True:
        destinatario = input('Para: ')
        mensagem = input('Mensagem: ')
        mensagem_enviar = f'{destinatario}:{mensagem}'
        mensagem_encriptada = criptografar_mensagem(chave_simetrica, mensagem_enviar.encode())
        socket_cliente.sendall(mensagem_encriptada)
except Exception as e:
    print(f'Erro: {e}')
finally:
    socket_cliente.close()
