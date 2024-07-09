from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import json

ARQUIVO_CHAVES = "chaves.txt"

# Função para descriptografar chaves de um arquivo TXT
def carregar_chaves_criptografadas(senha, arquivo=ARQUIVO_CHAVES):
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

# Solicitar a senha do usuário
senha = input("Digite a senha para descriptografar o arquivo de chaves: ")

# Carregar e exibir o conteúdo do arquivo de chaves
try:
    dados = carregar_chaves_criptografadas(senha)
    print("Conteúdo do arquivo de chaves:")
    print(json.dumps(dados, indent=4))
except Exception as e:
    print(f"Erro ao carregar chaves: {e}")
