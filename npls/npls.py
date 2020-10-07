# -*- coding: utf-8 -*-
"""
    Network Packet Logging System

    Main Module
"""

# importes
from scapy.all import *
import logging
import argparse
import sys
import platform
import datetime

# Import dos modulos
import modules

# Opcoes padrao da aplicacao
log_level = 'WARNING'
db_type = 'sqlite'
db_path = './data/'
db_datetime = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
hostname = platform.node()
db_filename = db_path + hostname + '_' + db_datetime
packet_filter = 'ip and (tcp or udp)'
decoder = None
db = None

interface = "Intel(R) Dual Band Wireless-AC 8260"

# Configuração inicial do logging
log = logging.getLogger(__name__)


def main(log_level, db_type):
    """
    TODO: Completar
    :param main_log_level:
    :param main_db_type:
    :return:
    """
    global decoder
    global db

    # Cria a classe de ligacao a base de dados
    log.debug(f'[+] A criar a classe db')
    db = modules.database.db.Db(log_level, db_type, db_filename)

    # Cria a classe do decoder
    log.debug(f'[+] A criar a classe decoder')
    decoder = modules.decoder.decoder.Decoder(log_level)

    log.info(f'[+] A iniciar a captura de pacotes')
    # Depois de capturar o pacote envia-o para o packet_decode
    sniff(prn=packet_decoder, filter=packet_filter,  iface=interface)


def packet_decoder(packet):
    global decoder
    global db

    # Envia o pacote recolhido para o decoder
    decoded_packet = decoder.decode(packet)

    # Envia o pacote decodificado para a base de dados
    db.db_insert(decoded_packet)


def close(*connection):
    """
    TODO: Completar os parametros
    (*connection) argument tuple packing, os argumentos sao transformados numa tuple
    :param connection:
    :return:
    """
    print(f'\n[-] A terminar o Network Packet Logging')
    log.warning(f'[-] A terminar o Network Packet Logging System')

    # Se for passada a conecao da db como argumento
    if len(connection) is not 0:
        # TODO: Chamar a classe para fechar a db
        log.info('[+] A fechar a base de dados')
        for conn in connection:
            try:
                db.close()
                log.info('[+] Base de dados fechada')
            except:
                log.error('[!] Nao foi possivel fechar a base de dados')
    try:
        log.info('[-] A terminar o Network Packet Logging - Via try')
        sys.exit()
    except KeyboardInterrupt:
        log.info('[-] A terminar o Network Packet Logging - Via except')
        sys.exit()


if __name__ == '__main__':
    """
       Esta rotina não é chamada se estiver a correr como modulo
       Tudo o que aqui está não e necessário caso esteja a correr como modulo
    """
    # Configuracao do modulo de logging:
    #   filename    -> Ficheiro onde vai escrever os logs
    #   format      -> Formato da string de log
    #   datetime    -> Formato da data do log
    #   level*       -> Nivel de log, o default e Warning
    #   filemode -> Modo de escrita no ficheiro o default e append
    # TODO: apagar o file mode para passar a fazer append, , filemode='w'
    logging.basicConfig(filename='logs/npls.log',
                        format='%(name)s - %(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%d-%b-%y %H:%M:%S', filemode='w')

    log.warning(f'==================== NPLS Start ====================')
    print(f'==================== NPLS Start ====================')
    log.info(f'[+] Systema de logging iniciado')

    # Cria o objeto parser
    parser = argparse.ArgumentParser()

    # Adiciona os argumentos
    # Todo: Adicionar opcoes, por exemplo tcp, udp ou arp
    parser.add_argument('-l', '--logging', help='Nivel de logging, critical, error, warning (default), info, debug')
    parser.add_argument('-d', '--database', help='Escolha da base de dados: sqlite (default), csv ou consola.')
    parser.add_argument('-f', '--filter', help='Escolha o filtro o default e IP e TCP ou UDP')

    # Executa o parser
    args = parser.parse_args()

    # Verificação dos argumentos de logging
    if args.logging:
        log.info(f'[+] Foi passado para o logging o argumento -> {args.logging}')
        # Coloca as opções em maiusculas
        log_level = args.logging.upper()
        if log_level == 'DEBUG' or log_level == 'D':
            log.setLevel(logging.DEBUG)
            log_level = 'DEBUG'
            log.warning('[+] aplicacao iniciada em modo DEBUG')
            print(f'\n[+] A iniciar em modo de debug')
        elif log_level == 'INFO' or log_level == 'I':
            log.setLevel(logging.INFO)
            log_level = 'INFO'
            log.warning('[+] aplicacao iniciada em modo INFO')
        elif log_level == 'WARNING' or log_level == 'W':
            log.setLevel(logging.WARNING)
            log_level = 'WARNING'
            log.warning('[+] aplicacao iniciada em modo WARNING')
        elif log_level == 'ERROR' or log_level == 'E':
            log.setLevel(logging.ERROR)
            log_level = 'ERROR'
            log.warning('[+] aplicacao iniciada em modo ERRO')
        elif log_level == 'CRITICAL' or log_level == 'C':
            log.setLevel(logging.CRITICAL)
            log_level = 'CRITICAL'
            log.warning('[+] aplicacao iniciada em modo CRITICAL')
        else:
            log.error(f'[-] A opcao escolhida nao e valida')
            parser.print_help()
            close()
    else:
        # Nivel de logging padrao
        log.info(f'[*] Nivel de login padrão, {log_level}')

    # Verificação dos argumentos para o tipo de base de dados
    if args.database:
        log.info(f'[+] Foi passado como argumento de base de dados -> {args.database}')
        # Coloca as opções em minusculas
        db_type = args.database.lower()
        if db_type == 'sqlite':
            log.info(f'[+] A base de dados escolhida foi {db_type}')
        elif db_type == 'csv':
            log.info(f'[+] A base de dados escolhida foi {db_type}')
        elif db_type == 'consola':
            log.info(f'[+] A base de dados escolhida foi {db_type}')
        else:
            log.error(f'[-] A opcao escolhida nao e valida')
            # Nenhuma das opcoes escolhidas para a base de dados e valida
            parser.print_help()
            close()
    else:
        log.info(f'[+] A usar base de dados padrao, {db_type}')

    # Verificação dos argumentos para o filtro de captura
    if args.filter:
        log.info(f'[+] Foi passado como filtro -> {args.filter}')
        # Coloca as opções em minusculas
        db_type = args.database.lower()
        packet_filter = args.filter

    main(log_level, db_type)
