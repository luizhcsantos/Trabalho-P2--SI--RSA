import threading

class ClienteManager:
    def __init__(self):
        self.clientes = {}
        self.lock = threading.Lock()

    def adicionar_cliente(self, nome, conn, chave_simetrica, chave_publica_rsa):
        with self.lock:
            self.clientes[nome] = (conn, chave_simetrica, chave_publica_rsa)

    def remover_cliente(self, nome):
        with self.lock:
            if nome in self.clientes:
                del self.clientes[nome]

    def obter_cliente(self, nome):
        with self.lock:
            return self.clientes.get(nome)

    def listar_clientes(self):
        with self.lock:
            return list(self.clientes.keys())
