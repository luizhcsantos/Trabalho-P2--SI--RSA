import socket
import threading
import signal
import time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Hash import SHA256
import random
import json
import os
import EntidadeCertificadora as ca  # Importa a entidade certificadora

# Configurações do servidor
HOST = 'localhost'
PORT = 5000
ARQUIVO_CHAVES = "chaves.txt"

# Geração de parâmetros Diffie-Hellman
primo = getPrime(2048)
gerador = 2

# Dicionário para armazenar clientes e suas chaves
clientes = {}

# Lock para manipular o dicionário de clientes
clientes_lock = threading.Lock()

# Variável de controle de execução
executando = True

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

# Função para salvar chaves em um arquivo TXT criptografado
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

# Função para descriptografar chaves de um arquivo TXT
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

# Função para tratar as conexões dos clientes
def tratar_cliente(conn, addr, senha):
    print(f'Nova conexão estabelecida com {addr}')
    
    # Enviar parâmetros primo e gerador para o cliente
    conn.sendall(f'{primo},{gerador}'.encode())
    
    # Gerar par de chaves Diffie-Hellman
    chave_privada_dh, chave_publica_dh = gerar_chave_dh(primo, gerador)
    chave_publica_cliente_dh = int(conn.recv(1024).decode())
    conn.sendall(f'{chave_publica_dh}'.encode())
    chave_simetrica = calcular_chave_compartilhada(chave_privada_dh, chave_publica_cliente_dh, primo)
    print('Chave simétrica estabelecida:', chave_simetrica.hex())

    # Receber o nome do cliente e a chave pública RSA criptografada
    dados_criptografados = conn.recv(2048)
    nome_cliente = descriptografar_mensagem(chave_simetrica, dados_criptografados).decode()
    chave_publica_cliente_rsa = RSA.import_key(conn.recv(2048))
    
    # Gerar par de chaves RSA para o cliente
    chave_privada_servidor_rsa, chave_publica_servidor_rsa = gerar_par_chaves_rsa()
    
    # Salvar chaves criptografadas
    salvar_chaves_criptografadas(nome_cliente, chave_privada_servidor_rsa, chave_publica_servidor_rsa, senha)
    
    # Assinar chave pública do cliente e gerar certificado
    ca.adicionar_certificado_cliente(nome_cliente, chave_publica_cliente_rsa.export_key(), chave_privada_ca)
    certificado_cliente = ca.carregar_certificados()[nome_cliente]
    conn.sendall(json.dumps(certificado_cliente).encode())
    
    with clientes_lock:
        clientes[nome_cliente] = (conn, chave_simetrica, chave_publica_cliente_rsa)
    print(f'Cliente {nome_cliente} registrado.')

    while True:
        try:
            mensagem_cifrada = conn.recv(2048)
            if not mensagem_cifrada:
                break
            mensagem_decifrada = descriptografar_mensagem(chave_simetrica, mensagem_cifrada).decode()
            if ':' in mensagem_decifrada:
                destinatario, conteudo = mensagem_decifrada.split(':', 1)
                print(f'{nome_cliente} para {destinatario}: {conteudo}')
                
                # Enviar mensagem ao destinatário
                with clientes_lock:
                    if destinatario in clientes:
                        conn_destinatario, chave_simetrica_destinatario, chave_publica_rsa_destinatario = clientes[destinatario]
                        mensagem_enviada = f'{nome_cliente}: {conteudo}'
                        mensagem_encriptada = criptografar_mensagem(chave_simetrica_destinatario, mensagem_enviada)
                        conn_destinatario.sendall(mensagem_encriptada)
                    else:
                        mensagem_encriptada = criptografar_mensagem(chave_simetrica, "Destinatário não encontrado")
                        conn.sendall(mensagem_encriptada)
            else:
                print(f'Mensagem no formato incorreto de {nome_cliente}: {mensagem_decifrada}')
                mensagem_encriptada = criptografar_mensagem(chave_simetrica, "Mensagem no formato incorreto")
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

# Função para lidar com o sinal de interrupção
def interromper_servidor(sig, frame):
    global executando
    executando = False
    socket_servidor.close()
    print("\nServidor interrompido.")
    os._exit(0)

# Configurar sinal de interrupção
signal.signal(signal.SIGINT, interromper_servidor)

# Configurar socket do servidor
socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_servidor.bind((HOST, PORT))
socket_servidor.listen()
print(f'Servidor ouvindo em {HOST}:{PORT}...')

# Pedir a senha para descriptografar o arquivo de chaves
while True:
    senha = input("Digite a senha para descriptografar o arquivo de chaves: ")
    try:
        chaves_existentes = carregar_chaves_criptografadas(senha)
        break
    except ValueError as e:
        print(e)
        print("Senha incorreta. Tente novamente.")

# Inicializar a CA
chave_privada_ca, certificados = ca.inicializar_ca()

while executando:
    try:
        socket_servidor.settimeout(1)
        conn, addr = socket_servidor.accept()
        conn.settimeout(None)
        thread_cliente = threading.Thread(target=tratar_cliente, args=(conn, addr, senha))
        thread_cliente.start()
    except socket.timeout:
        continue
    except Exception as e:
        if executando:
            print(f'Erro ao aceitar conexão: {e}')
