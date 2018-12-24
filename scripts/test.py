import argparse
import struct
from socket import socket, htons, htonl, ntohs, ntohl


PUT = 0x10
GET = 0x20
DEL = 0x30
ACK = 0x40
NACK = 0x50
EXP = 0x60


def send_put(sock, key, value):
    keylen = len(key)
    vallen = len(value)
    put = struct.pack(
        f'=BIHI{keylen}s{vallen}s',
        PUT,
        htonl(11 + keylen + vallen),
        htons(keylen),
        htonl(vallen),
        key.encode(),
        value.encode()
    )
    sock.send(put)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    payload = struct.unpack('=B', sock.recv(total_len - 5))

    return {
        'code': code,
        'total_len': total_len,
        'payload': payload
    }


def send_get(sock, key):
    keylen = len(key)
    get = struct.pack(
        f'=BIH{keylen}s',
        GET,
        htonl(7 + keylen),
        htons(keylen),
        key.encode()
    )
    sock.send(get)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    if code in (ACK, NACK):
        payload = struct.unpack('=B', sock.recv(total_len - 5))
    else:
        klen, vlen = struct.unpack('=HI', sock.recv(6))
        klen, vlen = ntohs(klen), ntohl(vlen)
        payload = struct.unpack(f'={klen}s{vlen}s', sock.recv(klen + vlen))

    return {
        'code': code,
        'total_len': total_len,
        'payload': payload
    }


def send_exp(sock, key, ttl):
    keylen = len(key)
    exp = struct.pack(
        f'=BIH{keylen}sH',
        EXP,
        htonl(9 + keylen),
        htons(keylen),
        key.encode(),
        htons(ttl)
    )
    sock.send(exp)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    if code in (ACK, NACK):
        payload = struct.unpack('=B', sock.recv(total_len - 5))
    else:
        klen, vlen = struct.unpack('=HI', sock.recv(6))
        klen, vlen = ntohs(klen), ntohl(vlen)
        payload = struct.unpack(f'={klen}s{vlen}s', sock.recv(klen + vlen))

    return {
        'code': code,
        'total_len': total_len,
        'payload': payload
    }


def send_del(sock, key):
    keylen = len(key)
    delete = struct.pack(
        f'=BIH{keylen}s',
        DEL,
        htonl(7 + keylen),
        htons(keylen),
        key.encode()
    )
    sock.send(delete)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    payload = struct.unpack('=B', sock.recv(total_len - 5))

    return {
        'code': code,
        'total_len': total_len,
        'payload': payload
    }

if __name__ == '__main__':
    sock = socket()
    sock.connect(('127.0.0.1', 9090))
    while True:
        command = input("> ")
        head, tail = command.split(' ', 1)
        if head.lower() == 'put':
            k, v = tail.split()
            print(send_put(sock, k, v))
        elif head.lower() == 'get':
            print(send_get(sock, tail))
        elif head.lower() == 'exp' or head.lower() == 'expire':
            k, t = tail.split()
            print(send_exp(sock, k, int(t)))
        else:
            send_del(sock, tail)
