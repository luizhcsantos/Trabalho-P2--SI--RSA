import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, long_to_bytes
from hashlib import sha256
import random

# Configurações do servidor
HOST = 'localhost'
PORT = 5000

# Gerar parâmetros primo e gerador para Diffie-Hellman
primo = getPrime(1024)
gerador = 2

# Dicionário para armazenar clientes e suas chaves
clientes = {}

# Lock para manipular o dicionário de clientes
clientes_lock = threading.Lock()

# Gerar par de chaves Diffie-Hellman
def gerar_chave_dh(primo, gerador):
    chave_privada = random.randint(1, primo - 1)
    chave_publica = pow(gerador, chave_privada, primo)
    return chave_privada, chave_publica

# Calcular a chave compartilhada
def calcular_chave_compartilhada(chave_privada, chave_publica, primo):
    chave_compartilhada = pow(chave_publica, chave_privada, primo)
    return sha256(long_to_bytes(chave_compartilhada)).digest()[:16]

# Função para tratar as conexões dos clientes
def tratar_cliente(conn, addr):
    print(f'Nova conexão estabelecida com {addr}')
    
    # Enviar parâmetros primo e gerador para o cliente
    conn.sendall(f'{primo},{gerador}'.encode())
    
    # Gerar par de chaves Diffie-Hellman
    chave_privada, chave_publica = gerar_chave_dh(primo, gerador)
    chave_publica_cliente = int(conn.recv(1024).decode())
    conn.sendall(f'{chave_publica}'.encode())
    chave_compartilhada = calcular_chave_compartilhada(chave_privada, chave_publica_cliente, primo)
    print('Chave compartilhada estabelecida:', chave_compartilhada.hex())

    # Receber o nome do cliente
    nome_cliente = descriptografar_mensagem(chave_compartilhada, conn.recv(2048))
    with clientes_lock:
        clientes[nome_cliente] = (conn, chave_compartilhada)
    print(f'Cliente {nome_cliente} registrado.')

    while True:
        try:
            mensagem_cifrada = conn.recv(2048)
            if not mensagem_cifrada:
                break
            mensagem_decifrada = descriptografar_mensagem(chave_compartilhada, mensagem_cifrada)
            if ':' in mensagem_decifrada:
                destinatario, conteudo = mensagem_decifrada.split(':', 1)
                print(f'{nome_cliente} para {destinatario}: {conteudo}')
                
                # Enviar mensagem ao destinatário
                with clientes_lock:
                    if destinatario in clientes:
                        conn_destinatario, chave_destinatario = clientes[destinatario]
                        mensagem_enviada = f'{nome_cliente}: {conteudo}'
                        mensagem_encriptada = criptografar_mensagem(chave_destinatario, mensagem_enviada)
                        conn_destinatario.sendall(mensagem_encriptada)
                    else:
                        mensagem_encriptada = criptografar_mensagem(chave_compartilhada, "Destinatário não encontrado")
                        conn.sendall(mensagem_encriptada)
            else:
                print(f'Mensagem no formato incorreto de {nome_cliente}: {mensagem_decifrada}')
                mensagem_encriptada = criptografar_mensagem(chave_compartilhada, "Mensagem no formato incorreto")
                conn.sendall(mensagem_encriptada)
        except Exception as e:
            print(f'Erro durante comunicação com {addr}: {e}')
            break
    
    with clientes_lock:
        del clientes[nome_cliente]
    conn.close()
    print(f'Conexão com {addr} encerrada')

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

# Configurar socket do servidor
socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_servidor.bind((HOST, PORT))
socket_servidor.listen()
print(f'Servidor ouvindo em {HOST}:{PORT}...')

while True:
    conn, addr = socket_servidor.accept()
    thread_cliente = threading.Thread(target=tratar_cliente, args=(conn, addr))
    thread_cliente.start()
