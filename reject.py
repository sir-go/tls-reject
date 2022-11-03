#!/usr/bin/env python3
# coding:utf8
import os

import pymysql as pm
from time import sleep, strftime, localtime
import socket
from netstack.packet import Packet, make_rst
from netstack.tls import ClientHello
from threading import Thread
from requests.models import PreparedRequest
import struct

env = os.environ.get

db_cfg = {
    "host": env('BLOCK_DB_HOST'),
    "user": env('BLOCK_DB_USERNAME'),
    "password": env('BLOCK_DB_PASSWORD'),
    "db": env('BLOCK_DB_NAME'),
    "charset": 'utf8mb4',
    "connect_timeout": 30
}

update_interval = env('BLOCK_UPD_INTERVAL', 10)
input_interface = env('BLOCK_IN_IF')
output_interface = env('BLOCK_OUT_IF')


def t_now() -> str:
    return strftime('%Y-%m-%d %H:%M:%S', localtime())


def update_list(ltime: int, d_list: set[str]) -> int:
    with pm.connect(**db_cfg) as conn:
        with conn.cursor() as cursor:
            cursor.execute('select time from events where event = '
                           '"update_https_domains"')
            last_upd_time = cursor.fetchone()
            if last_upd_time is not None \
                    and last_upd_time != ltime:
                cursor.execute('select hostname from https_domains')
                for r in cursor.fetchall():
                    req = PreparedRequest()
                    req.prepare_url('https://{}'.format(r[0]), None)
                    encoded = req.url.rstrip('/')[8:]
                    d_list.add(encoded)
                print('[{}] updated : {}'.format(t_now(), len(d_list)))
            return last_upd_time


def loop_update_list(timeout: float, *args, **kwargs):
    last_known_upd_time = 0
    while True:
        last_known_upd_time = update_list(last_known_upd_time, *args, **kwargs)
        sleep(timeout)


def proc_traffic(in_s: socket.socket, out_s: socket.socket,
                 d_list: set[str]) -> bool:
    received_data = in_s.recv(65535)
    if len(received_data) < 15:
        return False
    packet = Packet()
    try:
        packet.parse_from(received_data)
    except struct.error as e:
        print(e)
        return False

    if packet is None or packet.tcp is None:
        return False

    if packet.tcp.get_dst() not in [443]:
        return False

    if not packet.is_tls_client_hello():
        return False

    try:
        tls_hello = ClientHello(packet.payload.get_bytes())
        if tls_hello.server_name is None:
            return False
        if tls_hello.server_name.decode() not in d_list:
            return False
        print('[{}] denied {} from {}'.format(
            t_now(), tls_hello.server_name.decode(),
            packet.ip.get_src()))
        response = make_rst(packet)
        for i in range(0, 3):
            out_s.sendto(response, (packet.ip.get_src(), 0))
        return True
    except IndexError as e:
        print('[{}] parsing error'.format(t_now()), e)
        return False
    except Exception as e:
        print('[{}] other error'.format(t_now()), e)
        return False


def sniff(in_if, out_if, d_list):
    ipv4_etype_code = 0x0800
    raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                               socket.htons(ipv4_etype_code))
    in_dev_name = bytes(in_if, 'utf8') + b'\0'
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                          in_dev_name)
    os.system("ip link set {0} promisc on".format(in_if))

    output_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
    out_dev_name = bytes(out_if, 'utf8') + b'\0'
    output_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                             out_dev_name)

    while True:
        proc_traffic(raw_socket, output_socket, d_list)


if __name__ == '__main__':
    print('[{}] -- start --'.format(t_now()))
    deny_list = set()

    t_upd = Thread(target=loop_update_list,
                   args=(update_interval, deny_list))
    t_upd.start()

    t_sniff = Thread(target=sniff,
                     args=(input_interface, output_interface, deny_list))
    t_sniff.start()
