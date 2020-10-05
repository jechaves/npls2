# -*- coding: utf-8 -*-
"""
    Network Packet Logging System

    Decoder
"""

# imports
from scapy.all import *
import logging
import datetime
import socket
import geoip2.database
import geoip2.errors
import ipaddress

# Configuração inicial do logging
log = logging.getLogger(__name__)


class Decoder:
    """
        Class para descodificar os pacotes
    """

    def __init__(self, decoder_log_level):
        self.log_level = decoder_log_level
        # Configura o nivel de logging do modulo
        self.decoder_log_level()

        # Abre a base de dados de geolocalizacao
        log.info('[+] A iniciar a abertura da base de dados de geolocalizacao')
        try:
            self.geoip_reader = geoip2.database.Reader('./resources/GeoLite2/GeoLite2-City.mmdb')
            log.info('[+] Base de dados de geolocalizacao aberta com sucesso')
        except:
            log.error('[!] Nao foi possivel abrir a base de dados da geolocalizacao')
            print('[!] Nao foi possivel abrir a base de dados da geolocalizacao')

        # Inicia o contador de pacotes
        self.packet_number = 0
        # Inicia o dicionario
        self.packet_dic = {}
        # Inicia o timestamp
        self.timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')

    def decoder_log_level(self):
        """
            Configura o nivel de logging do modulo
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

    def decode(self, packet):
        """

        :param packet:
        :return:
        """
        # coloca o numero do pacote e o timestamp
        self.packet_dic = {'packet_number': self.packet_number, 'time_stamp': self.timestamp}

        # Retira os dados com cabecalho de layer 3
        if packet.haslayer(IP):
            self.packet_dic['l3_layer'] = 'ip'
            self.packet_dic['ip_version'] = packet.getlayer(IP).version
            self.packet_dic['ip_len'] = packet.getlayer(IP).len
            self.packet_dic['ip_flags'] = packet.sprintf("%IP.flags%")
            self.packet_dic['ip_frag'] = packet.getlayer(IP).frag
            self.packet_dic['ip_proto'] = packet.getlayer(IP).proto
            self.packet_dic['ip_src'] = packet.getlayer(IP).src
            self.packet_dic['ip_address_type_src'] = self.decode_ip_address_type(self.packet_dic['ip_src'])
            if self.packet_dic['ip_address_type_src'] == 'global':
                packet_location = self.decode_geolocation(self.packet_dic.get('ip_src'))
                self.packet_dic['ip_geolocalizacao_src_pais'] = packet_location[0]
                self.packet_dic['ip_geolocalizacao_src_pais_iso'] = packet_location[1]
                self.packet_dic['ip_geolocalizacao_src_cidade'] = packet_location[2]
            self.packet_dic['ip_dst'] = packet.getlayer(IP).dst
            self.packet_dic['ip_address_type_dst'] = self.decode_ip_address_type(self.packet_dic['ip_dst'])
            if self.packet_dic['ip_address_type_dst'] == 'global':
                packet_location = self.decode_geolocation(self.packet_dic.get('ip_dst'))
                self.packet_dic['ip_geolocalizacao_dst_pais'] = packet_location[0]
                self.packet_dic['ip_geolocalizacao_dst_pais_iso'] = packet_location[1]
                self.packet_dic['ip_geolocalizacao_dst_cidade'] = packet_location[2]

            # Retira os dados com cabecalho TCP de layer 4
            if packet.haslayer(TCP):
                self.packet_dic['l4_layer'] = 'tcp'
                self.packet_dic['l4_sport'] = packet.getlayer(TCP).sport
                self.packet_dic['l4_sport_name'] = self.decode_port_name(self.packet_dic.get('l4_sport'),
                                                                         self.packet_dic.get('l4_layer'))
                self.packet_dic['l4_dport'] = packet.getlayer(TCP).dport
                self.packet_dic['l4_dport_name'] = self.decode_port_name(self.packet_dic.get('l4_dport'),
                                                                         self.packet_dic.get('l4_layer'))
                # self.packet_dic['tcp_flags'] = packet.getlayer(TCP).flags
                self.packet_dic['tcp_flags'] = packet.sprintf("%TCP.flags%")

            # Retira os dados com cabecalho UDP de layer 4
            elif packet.haslayer(UDP):
                self.packet_dic['l4_layer'] = 'udp'
                self.packet_dic['l4_sport'] = packet.getlayer(UDP).sport
                self.packet_dic['l4_dport'] = packet.getlayer(UDP).dport

            else:
                self.packet_dic['l4_layer'] = 'unknown'

        elif packet.haslayer(ARP):
            self.packet_dic['l3_layer'] = 'arp'

        elif packet.haslayer(IPv6):
            self.packet_dic['l3_layer'] = 'ipv6'

        else:
            self.packet_dic['l3_layer'] = 'unknown'

        # print(f'{self.packet_dic.get("packet_number")} - {self.packet_dic.get("time_stamp")} src: {self.packet_dic.get("ip_src")} -> dst: {self.packet_dic.get("ip_dst")} -> {self.packet_dic.get("l4_layer")}')

        self.packet_number += 1

        return self.packet_dic

    # Retorna o nome da port
    def decode_port_name(self, port_number, port_name):
        """

        :param port_number:
        :param port_name:
        :return:
        """
        try:
            decoded_port_name = socket.getservbyport(port_number, port_name)
        except socket.error:
            decoded_port_name = 'Unknown'

        return decoded_port_name

    # Retorna a localizacao do IP
    def decode_geolocation(self, ip):
        try:
            self.geoip_ip_location = self.geoip_reader.city(ip)
            self.ip_country = self.geoip_ip_location.country.name
            self.ip_country_iso = self.geoip_ip_location.country.iso_code
            self.ip_city = self.geoip_ip_location.city.name

        except geoip2.errors as e:
            log.error(f'[!] Erro {e} a localizar o IP')

        return self.ip_country, self.ip_country_iso, self.ip_city

    # Retorna o tipo de endereceo IP
    def decode_ip_address_type(self, ip):

        if ipaddress.IPv4Address(ip).is_private:
            ip_address_type = 'private'
        elif ipaddress.IPv4Address(ip).is_multicast:
            ip_address_type = 'multicast'
        elif ipaddress.IPv4Address(ip).is_loopback:
            ip_address_type = 'loopback'
        elif ipaddress.IPv4Address(ip).is_link_local:
            ip_address_type = 'local_link'
        elif ipaddress.IPv4Address(ip).is_reserved:
            ip_address_type = 'reserved'
        elif ipaddress.IPv4Address(ip).is_global:
            ip_address_type = 'global'
        elif ipaddress.IPv4Address(ip).is_unspecified:
            ip_address_type = 'unspecified'
        else:
            ip_address_type = 'undefined'

        return ip_address_type


if __name__ == '__main__':
    logging.basicConfig(filename='../logs/module_decoder.log',
                        format='%(name)s - %(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%d-%b-%y %H:%M:%S')
    log.setLevel(logging.DEBUG)
    log.warning(f'==================== Module Start ====================')
    log.info(f'[+] Systema de logging iniciado')
    log.info('[!] Modulo a correr em modo local')

    log_level = 'DEBUG'
    db_type = 'sqlite'
    test = 'teste'

    decoder = Decoder(log_level)

    decoder.decode(test)
    decoder.decode(test)
    decoder.decode(test)
    decoder.decode(test)
