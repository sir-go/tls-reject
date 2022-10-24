#!/usr/bin/env python3
# coding:utf8
import os

import pymysql as pm
from time import sleep, strftime, localtime
import socket
from netstack.packet import Packet, make_response
from netstack.tls import HANDSHAKE, CLIENT_HELLO, ClientHello
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


def tnow():
    return strftime('%Y-%m-%d %H:%M:%S', localtime())


def update_list(db_conf, d_list, timeout):
    conn = None

    last_known_upd_time = 0
    while True:
        try:
            conn = pm.connect(**db_conf)
            with conn.cursor() as cursor:
                cursor.execute('select time from events where event = "update_https_domains"')
                last_upd_time = cursor.fetchone()
                # print(last_upd_time)

                if last_upd_time is not None and last_upd_time != last_known_upd_time:
                    cursor.execute('select hostname from https_domains')
                    for r in cursor.fetchall():
                        req = PreparedRequest()
                        req.prepare_url('https://{}'.format(r[0]), None)
                        encoded = req.url.rstrip('/')[8:]
                        # d_list.clear()
                        d_list.add(encoded)
                    print('[{}] updated : {}'.format(tnow(), len(d_list)))
                last_known_upd_time = last_upd_time
        finally:
            if conn is not None:
                conn.close()
        sleep(timeout)


def sniff(in_if, out_if, d_list):
    ipv4_etype_code = 0x0800
    raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ipv4_etype_code))
    in_dev_name = bytes(in_if, 'utf8') + b'\0'
    # print(in_dev_name)
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, in_dev_name)
    os.system("ip link set {0} promisc on".format(in_if))

    output_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    out_dev_name = bytes(out_if, 'utf8') + b'\0'
    # print(out_dev_name)
    output_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, out_dev_name)

    while True:
        received_data = raw_socket.recv(65535)
        if len(received_data) < 15:
            continue
        packet = Packet()
        try:
            packet.parse_from(received_data)
        except struct.error as e:
            print(e)
            continue
        if packet is None or packet.tcp is None:
            continue

        if packet.tcp.get_dst() in [443] \
                and packet.tcp.has_flag('ack')\
                and packet.tcp.has_flag('psh') \
                and packet.has_payload() \
                and packet.payload.len > 5 \
                and packet.payload.get_bytes()[0] == HANDSHAKE \
                and packet.payload.get_bytes()[5] == CLIENT_HELLO:
            try:
                tls_hello = ClientHello(packet.payload.get_bytes())
                if tls_hello.server_name is not None:
                    if tls_hello.server_name.decode() in d_list:
                        print('[{}] denied {} from {}'.format(tnow(), tls_hello.server_name.decode(), packet.ip.get_src()))
                        response = make_response(packet, reset=True)
                        for i in range(0, 3):
                            output_socket.sendto(response, (packet.ip.get_src(), 0))
                        # print('https', tls_hello.server_name, packet)
            except IndexError as e:
                print('[{}] parsing error'.format(tnow()))
                print(e)
            except Exception as e:
                print('[{}] other error'.format(tnow()))
                print(e)


print('[{}] -- start --'.format(tnow()))
deny_list = set()

t_upd = Thread(target=update_list, args=(db_cfg, deny_list, update_interval))
t_upd.start()

t_sniff = Thread(target=sniff, args=(input_interface, output_interface, deny_list))
t_sniff.start()
