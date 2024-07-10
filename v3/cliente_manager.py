class ClienteManager:
    def __init__(self):
        self.clientes = {}

    def adicionar_cliente(self, nome, conn, chave_simetrica, chave_publica):
        self.clientes[nome] = (conn, chave_simetrica, chave_publica)

    def remover_cliente(self, nome):
        if nome in self.clientes:
            del self.clientes[nome]

    def obter_cliente(self, nome):
        return self.clientes.get(nome)
