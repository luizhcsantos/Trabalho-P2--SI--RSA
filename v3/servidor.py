import socket
import threading
import signal
import time
import os
import json
from cliente_manager import ClienteManager
from ca import CA
from criptografia import (
    criptografar_mensagem, descriptografar_mensagem,
    gerar_chave_dh, calcular_chave_compartilhada,
    gerar_par_chaves_rsa, salvar_chaves_criptografadas, carregar_chaves_criptografadas, inicializar_arquivo_chaves,
    verificar_nonce_e_tempo
)
from Crypto.PublicKey import RSA

# Configurações do servidor
HOST = '0.0.0.0'
PORT = 5000
ARQUIVO_CHAVES = "chaves.txt"

# Geração de parâmetros Diffie-Hellman
primo = 23  # getPrime(2048)
gerador = 5  # 2

class Servidor:
    def __init__(self, host, port, arquivo_chaves, ca):
        self.host = host
        self.port = port
        self.arquivo_chaves = arquivo_chaves
        self.cliente_manager = ClienteManager()
        self.ca = ca
        self.executando = True

        self.socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_servidor.bind((self.host, self.port))
        self.socket_servidor.listen()

        signal.signal(signal.SIGINT, self.interromper_servidor)
        print(f'Servidor ouvindo em {self.host}:{self.port}...')

    def iniciar(self):
        while self.executando:
            try:
                self.socket_servidor.settimeout(1)
                conn, addr = self.socket_servidor.accept()
                conn.settimeout(None)
                thread_cliente = threading.Thread(target=self.tratar_cliente, args=(conn, addr))
                thread_cliente.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.executando:
                    print(f'Erro ao aceitar conexão: {e}')

    def interromper_servidor(self, sig, frame):
        self.executando = False
        self.socket_servidor.close()
        print("\nServidor interrompido.")
        os._exit(0)

    def tratar_cliente(self, conn, addr):
        print(f'Nova conexão estabelecida com {addr}')
        try:
            # Enviar parâmetros primo e gerador para o cliente
            conn.sendall(f'{primo},{gerador}'.encode())

            # Gerar par de chaves Diffie-Hellman
            chave_privada_dh, chave_publica_dh = gerar_chave_dh(primo, gerador)
            chave_publica_cliente_dh = int(conn.recv(1024).decode())
            conn.sendall(f'{chave_publica_dh}'.encode())
            chave_simetrica = calcular_chave_compartilhada(chave_privada_dh, chave_publica_cliente_dh, primo)
            print('Chave simétrica estabelecida:', chave_simetrica.hex())

            # Receber o nome do cliente, chave pública RSA, nonce e carimbo de tempo criptografados
            dados_criptografados = conn.recv(2048)
            dados_decifrados = descriptografar_mensagem(chave_simetrica, dados_criptografados).decode().split(',')
            nome_cliente = dados_decifrados[0]
            nonce = bytes.fromhex(dados_decifrados[1])
            carimbo_tempo = dados_decifrados[2].encode()

            # Verificar nonce e carimbo de tempo
            if not verificar_nonce_e_tempo(nonce, carimbo_tempo):
                print(f'Nonce ou carimbo de tempo inválido de {addr}')
                conn.close()
                return

            chave_publica_cliente_rsa = RSA.import_key(conn.recv(2048))

            # Gerar par de chaves RSA para o cliente
            chave_privada_servidor_rsa, chave_publica_servidor_rsa = gerar_par_chaves_rsa()

            # Salvar chaves criptografadas
            salvar_chaves_criptografadas(nome_cliente, chave_privada_servidor_rsa, chave_publica_servidor_rsa, senha)

            # Assinar chave pública do cliente e gerar certificado
            self.ca.adicionar_certificado_cliente(nome_cliente, chave_publica_cliente_rsa.export_key(), self.ca.chave_privada.export_key())
            certificado_cliente = self.ca.carregar_certificados()[nome_cliente]
            conn.sendall(json.dumps(certificado_cliente).encode())

            self.cliente_manager.adicionar_cliente(nome_cliente, conn, chave_simetrica, chave_publica_cliente_rsa)
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
                        cliente = self.cliente_manager.obter_cliente(destinatario)
                        if cliente:
                            conn_destinatario, chave_simetrica_destinatario, _ = cliente
                            mensagem_enviada = f'{nome_cliente}: {conteudo}'
                            mensagem_encriptada = criptografar_mensagem(chave_simetrica_destinatario, mensagem_enviada.encode())
                            conn_destinatario.sendall(mensagem_encriptada)
                        else:
                            mensagem_encriptada = criptografar_mensagem(chave_simetrica, "Destinatário não encontrado".encode())
                            conn.sendall(mensagem_encriptada)
                    else:
                        print(f'Mensagem no formato incorreto de {nome_cliente}: {mensagem_decifrada}')
                        mensagem_encriptada = criptografar_mensagem(chave_simetrica, "Mensagem no formato incorreto".encode())
                        conn.sendall(mensagem_encriptada)
                except Exception as e:
                    print(f'Erro durante comunicação com {addr}: {e}')
                    break

            self.cliente_manager.remover_cliente(nome_cliente)
            conn.close()
            print(f'Conexão com {addr} encerrada')
        except Exception as e:
            print(f'Erro ao tratar cliente {addr}: {e}')
            conn.close()

# Pedir a senha para descriptografar o arquivo de chaves
while True:
    senha = input("Digite a senha para descriptografar o arquivo de chaves: ")
    try:
        inicializar_arquivo_chaves(senha)  # Inicializa o arquivo se ele não existir
        chaves_existentes = carregar_chaves_criptografadas(senha)
        break
    except ValueError as e:
        print(e)
        print("Senha incorreta. Tente novamente.")

# Inicializar a CA
ca = CA()

# Inicializar o servidor
servidor = Servidor(HOST, PORT, ARQUIVO_CHAVES, ca)
servidor.iniciar()
