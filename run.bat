@echo off

:: Ativar o ambiente virtual
call p2\Scripts\activate

:: Navegar para a pasta v2 e executar o arquivo python
cd v2
python servidor.py

:: Retornar à pasta raiz
cd ..
