import os
import time

def gerar_nonce(tamanho=16):
    return os.urandom(tamanho)

def gerar_carimbo_tempo():
    return str(time.time()).encode()

nonce = gerar_nonce()
carimbo_tempo = gerar_carimbo_tempo()

# Incluir nonce e carimbo de tempo na mensagem
mensagem = b'mensagem de teste' + nonce + carimbo_tempo
