# -*- coding: utf-8 -*-
"""
    Network Packet Logging System

    Decoder
"""

# imports
import logging
import platform
import datetime
import sqlite3

# Configuração inicial do logging
log = logging.getLogger(__name__)

# Query para criar as tabelas
sqlite_create_table_query = '''
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        packet_number INTEGER,
                        time_stamp TEXT,
                        l3_layer TEXT,
                        ip_version TEXT,
                        ip_len TEXT,
                        ip_flags TEXT,
                        ip_frag TEXT,
                        ip_proto TEXT,
                        ip_src TEXT,
                        ip_address_type_src TEXT,
                        ip_geolocalizacao_src_pais TEXT,
                        ip_geolocalizacao_src_pais_iso TEXT,
                        ip_geolocalizacao_src_cidade TEXT,
                        ip_dst TEXT,
                        ip_address_type_dst TEXT,
                        ip_geolocalizacao_dst_pais TEXT,
                        ip_geolocalizacao_dst_pais_iso TEXT,
                        ip_geolocalizacao_dst_cidade TEXT,
                        l4_layer TEXT,
                        l4_sport TEXT,
                        l4_Sport_name TEXT,
                        l4_dport TEXT,
                        l4_dport_name TEXT,
                        tcp_flags TEXT
                    );
                    '''


class Db:
    '''
    Classe que vai tratar da base de dados.
    '''

    def __init__(self, db_log_level, db_db_type, db_db_filename):
        '''
        Construtor da classe

        :param db_log_level: Nivel de logging do modulo
        :param db_db_type: Tipo de base de dados a ser criada, SQLite, CSV ou Consola
        :param db_db_filename: Nome da base de dados
        '''

        # Variaveis passadas a classe
        self.log_level = db_log_level
        self.db_type = db_db_type
        self.db_filename = db_db_filename

        # Variaveis inicializadas de modo a que possam ser usadas por toda a classe
        self.db_conn = None
        self.db_cursor = None

        # Configura o nivel de logging do modulo
        self.db_log_level()

        # Chama a funcao que queria a base de dados selecionada
        log.debug(f'[*] Base de dados: {self.db_type}')
        if self.db_type == 'csv':
            self.db_csv_create()
        elif self.db_type == 'sqlite':
            self.db_sqlite_create()
        else:
            log.error(f'[!] Nao foi escolhida nenhuma dase de dados')

    def db_log_level(self):
        """
        Configura o nivel de logging do modulo para ficar igual ao da aplicação.

        :return: Null
        """

        if self.log_level == 'DEBUG' or self.log_level == 'D':
            log.setLevel(logging.DEBUG)
            log.warning(f'[+] Modulo {__name__} iniciado em modo DEBUG')
            print(f'\n[+] A iniciar {__name__} em modo de debug')
        elif self.log_level == 'INFO' or self.log_level == 'I':
            log.setLevel(logging.INFO)
            log.warning(f'[+] Modulo {__name__} iniciado em modo INFO')
        elif self.log_level == 'WARNING' or self.log_level == 'W':
            log.setLevel(logging.WARNING)
            log.warning(f'[+] Modulo {__name__} iniciado em modo WARNING')
        elif self.log_level == 'ERROR' or self.log_level == 'E':
            log.setLevel(logging.ERROR)
            log.warning(f'[+] Modulo {__name__} iniciado em modo ERRO')
        elif self.log_level == 'CRITICAL' or self.log_level == 'C':
            log.setLevel(logging.CRITICAL)
            log.warning(f'[+] Modulo {__name__} iniciado em modo CRITICAL')
        else:
            log.error(f'[-] A opcao escolhida nao e valida')

    def db_sqlite_create(self):
        """
        Cria a base de dados SQLite

        :return: Null
        """

        log.debug(f'[+] A iniciar a criacao da base de dados SQLite')

        # Cria o nome do ficheiro de base de dados SQLite
        sqlite_db_filename = self.db_filename + '.sqlite'

        # Tenta criar a ligação a base de dados
        try:
            log.info(f'[+] A criar a base de dados')

            # Criacao e ligacao a base de dados SQLite
            self.db_conn = sqlite3.connect(sqlite_db_filename)
            log.info(f'[+] Ligacao a base de dados com sucesso')
        except sqlite3.Error as e:
            log.error(f'[!] Ocureu o erro {e} na criacao da base de dados')

        # Tenta criar as tabelas na base de dados
        try:
            self.db_sqlite_table()
        except sqlite3.Error as e:
            log.error(f'[!] Ocureu o erro {e} na criacao das tabelas')

    def db_sqlite_table(self):
        """
        Cria as tabelas na base de dados SQLite.

        :return: Null
        """

        log.info(f'[+] A criar tabelas na base de dados SQLite')

        # Cursor de escrita na base de dados
        self.db_cursor = self.db_conn.cursor()
        try:
            self.db_cursor.execute(sqlite_create_table_query)
            self.db_conn.commit()
            log.info(f'[+] Criada a tabela na base de dados com sucesso')
        except sqlite3.Error as e:
            log.error(f'[!] Ocureu o erro {e} na criacao das tabelas')

    def db_csv_create(self):
        """
        Cria a base de dados CSV

        :return: Null
        """

        log.debug(f'[+] A iniciar a criacao da base de dados CSV')

        # Cria o nome do ficheiro de base de dados CSV
        csv_db_filename = self.db_filename + '.csv'
        try:
            log.info(f'[+] A criar ficheiro de base de dados')
            log.debug(f'[*] Nome da db: {self.db_filename}')
            # Cria o ficheiro
            self.db_conn = open(csv_db_filename, "w")
            log.debug(f'[+] Foi criado o ficheiro {csv_db_filename}')
        except:
            log.error(f'[!] Nao foi possivel abrir o ficheiro para escrita.')
            print(f'[!] Nao foi possivel abrir o ficheiro para escrita.')

        try:
            # Cria os heather no ficheiro
            self.db_csv_header()
        except:
            log.error(f'[!] Nao foi possivel abrir o ficheiro para criar o heather.')
            print(f'[!] Nao foi possivel abrir o ficheiro para criar o heather.')

    # Cria o heather no ficheiro CSV
    def db_csv_header(self):
        """

        :return:
        """
        log.info(f'[+] Criacao do heather no ficheiro CSV')
        self.db_conn.write(f'packet_number,time_stamp,'
                           f'l3_layer,ip_version,ip_len,ip_flags,ip_frag,ip_proto,'
                           f'ip_src,ip_address_type_src,'
                           f'ip_geolocalizacao_src_pais,ip_geolocalizacao_src_pais_iso,ip_geolocalizacao_src_cidade,'
                           f'ip_dst,ip_address_type_dst,'
                           f'ip_geolocalizacao_dst_pais,ip_geolocalizacao_dst_pais_iso,ip_geolocalizacao_dst_cidade,'
                           f'l4_layer,l4_sport,l4_sport_name,l4_dport,l4_dport_name,tcp_flags\n')

    # Insere os dados na base de dados
    def db_insert(self, db_packet_dic):

        if self.db_type == 'csv':
            self.db_conn.write(f'{str(db_packet_dic.get("packet_number"))},'
                               f'{str(db_packet_dic.get("time_stamp"))},'
                               f'{str(db_packet_dic.get("l3_layer"))},'
                               f'{str(db_packet_dic.get("ip_version"))},'
                               f'{str(db_packet_dic.get("ip_len"))},'
                               f'{str(db_packet_dic.get("ip_flags"))},'
                               f'{str(db_packet_dic.get("ip_frag"))},'
                               f'{str(db_packet_dic.get("ip_proto"))},'
                               f'{str(db_packet_dic.get("ip_src"))},'
                               f'{str(db_packet_dic.get("ip_address_type_src"))},'
                               f'{str(db_packet_dic.get("ip_geolocalizacao_src_pais"))},'
                               f'{str(db_packet_dic.get("ip_geolocalizacao_src_pais_iso"))},'
                               f'{str(db_packet_dic.get("ip_geolocalizacao_src_cidade"))},'
                               f'{str(db_packet_dic.get("ip_dst"))},'
                               f'{str(db_packet_dic.get("ip_address_type_dst"))},'
                               f'{str(db_packet_dic.get("ip_geolocalizacao_dst_pais"))},'
                               f'{str(db_packet_dic.get("ip_geolocalizacao_dst_pais_iso"))},'
                               f'{str(db_packet_dic.get("ip_geolocalizacao_dst_cidade"))},'
                               f'{str(db_packet_dic.get("l4_layer"))},'
                               f'{str(db_packet_dic.get("l4_sport"))},'
                               f'{str(db_packet_dic.get("l4_sport_name"))},'
                               f'{str(db_packet_dic.get("l4_dport"))},'
                               f'{str(db_packet_dic.get("l4_dport_name"))},'
                               f'{str(db_packet_dic.get("tcp_flags"))}'
                               f'\n'
                               )

        elif self.db_type == 'sqlite':
            # Query para inserir pacotes na base de dados
            sqlite_insert_query = f'''
                                INSERT
                                    INTO packets(
                                        packet_number,
                                        time_stamp,
                                        l3_layer,
                                        ip_version,
                                        ip_len,
                                        ip_flags,
                                        ip_frag,
                                        ip_proto,
                                        ip_src,
                                        ip_address_type_src,
                                        ip_geolocalizacao_src_pais,
                                        ip_geolocalizacao_src_pais_iso,
                                        ip_geolocalizacao_src_cidade,
                                        ip_dst,
                                        ip_address_type_dst,
                                        ip_geolocalizacao_dst_pais,
                                        ip_geolocalizacao_dst_pais_iso,
                                        ip_geolocalizacao_dst_cidade,
                                        l4_layer,
                                        l4_sport,
                                        l4_sport_name,
                                        l4_dport,
                                        l4_dport_name,
                                        tcp_flags)
                                    VALUES (
                                        ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                            '''
            # Sanitizacao dos campos a inserir na base de dados
            sqlite_insert_packet = (str(db_packet_dic.get("packet_number")),
                                    str(db_packet_dic.get('time_stamp')),
                                    str(db_packet_dic.get('l3_layer')),
                                    str(db_packet_dic.get("ip_version")),
                                    str(db_packet_dic.get("ip_len")),
                                    str(db_packet_dic.get("ip_flags")),
                                    str(db_packet_dic.get("ip_frag")),
                                    str(db_packet_dic.get("ip_proto")),
                                    str(db_packet_dic.get("ip_src")),
                                    str(db_packet_dic.get("ip_address_type_src")),
                                    str(db_packet_dic.get("ip_geolocalizacao_src_pais")),
                                    str(db_packet_dic.get("ip_geolocalizacao_src_pais_iso")),
                                    str(db_packet_dic.get("ip_geolocalizacao_src_cidade")),
                                    str(db_packet_dic.get("ip_dst")),
                                    str(db_packet_dic.get("ip_address_type_dst")),
                                    str(db_packet_dic.get("ip_geolocalizacao_dst_pais")),
                                    str(db_packet_dic.get("ip_geolocalizacao_dst_pais_iso")),
                                    str(db_packet_dic.get("ip_geolocalizacao_dst_cidade")),
                                    str(db_packet_dic.get("l4_layer")),
                                    str(db_packet_dic.get("l4_sport")),
                                    str(db_packet_dic.get("l4_sport_name")),
                                    str(db_packet_dic.get("l4_dport")),
                                    str(db_packet_dic.get("l4_dport_name")),
                                    str(db_packet_dic.get("tcp_flags")))
            try:
                self.db_cursor.execute(sqlite_insert_query, sqlite_insert_packet)
                self.db_conn.commit()
            except sqlite3.Error as e:
                log.error(f'[!] Ocureu o erro {e} a inserir o pacote na base de dados')

        else:
            log.error(f'[!] Base de dados desconhecida')

    # Fecha a base de dados
    def db_close(self):
        self.db_conn.close()


if __name__ == '__main__':
    logging.basicConfig(filename='../logs/module_db.log',
                        format='%(name)s - %(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%d-%b-%y %H:%M:%S')
    log.setLevel(logging.DEBUG)
    log.warning(f'==================== Module Start ====================')
    log.info(f'[+] Systema de logging iniciado')
    log.info('[!] Modulo a correr em modo local')

    log_level = 'DEBUG'
    db_type = 'csv'
    db_path = '../data/'
    db_datetime = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    hostname = platform.node()
    db_filename = db_path + hostname + '_' + db_datetime

    db = Db(log_level, db_type, db_filename)
    packet_dic = {"packet_number": "1", "time_stamp": "2020-04-15 00:55:19.323509"}
    db.db_insert(packet_dic)
