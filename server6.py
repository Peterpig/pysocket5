# -*- coding: utf-8 -*-
import gevent; from gevent import monkey; monkey.patch_all()
import select
import socket
from gevent.server import StreamServer
import requests
import struct


APPLY_IP_V4 = 1
APPLY_DOMAINNAME = 3
APPLY_IP_V6 = 4


class SocketServer(object):

    def __init__(self, server_addr='127.0.0.1', server_port=4444):
        self.BUFFER = 4096
        self.server_addr = server_addr
        self.server_port = server_port
        self.server = StreamServer((self.server_addr, self.server_port), self.handle)

    def process_version_and_auth(self, client_socket):
        data = client_socket.recv(self.BUFFER)
        socket_version = data[0]

        # socket 5
        assert socket_version == 5, 'Socket Version Error %s' %  socket_version

        # 无验证需求
        client_socket.send(b"\x05\x00")

    def connect_remote_server_and_replay(self, client_socket, addr, port):
        # 让客户端仍然绑定该地址
        server_hex_addr = socket.inet_aton(addr)
        server_hex_port = struct.pack(">H", port)

        try:
            remote_server_socket = socket.create_connection((addr, port))
            send_msg = b"\x05\x00\x00\x01" + server_hex_addr + server_hex_port
            client_socket.send(send_msg)
            return remote_server_socket
        except:
            print('e === ', e)
            send_msg = b"\x05\x01\x00\x01" + server_hex_addr + server_hex_port
            client_socket.send(send_msg)
            g = gevent.getcurrent()
            g.kill()

    def process_parse_client_info(self, client_socket):
        data = client_socket.recv(self.BUFFER)
        socket_version = data[0]
        cmd = data[1]
        keep = data[2]
        addr_type = data[3]
        domain_name = ''

        # get addr
        if addr_type == APPLY_IP_V4:
            addr = socket.inet_ntoa(data[4:8])
        elif addr_type == APPLY_DOMAINNAME:
            addr_len = data[4]
            domain_name = data[5: 5+addr_len]
            addr = socket.gethostbyname(domain_name)
        else:
            assert 1 != 1 , 'not support IPV6'

        # get port
        port = data[-2] * 256 + data[-1]

        assert cmd == 1, 'just support connect'
        info = {
            "domain_name": domain_name,
            "addr": addr,
            "port": port,
        }
        print('req domain_name: %(domain_name)s  addr: %(addr)s port: %(port)s' % (info))

        return self.connect_remote_server_and_replay(client_socket, addr, port)

    def send_all(self, sock, data):
        bytes_send = 0
        while True:
            res = sock.send(data[bytes_send:])
            if res < 0:
                return res
            bytes_send += res
            if bytes_send == len(data):
                return bytes_send

    def msg(self, client, remote):
        input = [client, remote]
        try:
            while True:
                in_rady, _, _ = select.select(input, [], [])
                if client in in_rady:
                    data = client.recv(self.BUFFER)
                    if len(data) <= 0:
                        break
                    remote.sendall(data)

                if remote in in_rady:
                    data = remote.recv(self.BUFFER)
                    if len(data) <= 0:
                        break
                    client.sendall(data)
        finally:
            client.close()
            remote.close()

    def handle(self, client_socket, address):
        try:
            self.process_version_and_auth(client_socket)
            remote_server_socket = self.process_parse_client_info(client_socket)
            self.msg(client_socket, remote_server_socket)
        except AssertionError:
            client_socket.close()
            g = gevent.getcurrent()
            g.kill()

    def serve_forever(self):
        self.server.serve_forever()

    def send_or_recv_msg(self, recv, send):
        data = recv.recv(self.BUFFER)
        if not data:
            recv.close()
            send.close()

        send.sendall(data)
        g = gevent.getcurrent()
        g.kill()

if __name__ == '__main__':
    s = SocketServer()
    s.serve_forever()