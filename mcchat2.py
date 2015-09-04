#!/usr/bin/env python2.7

from __future__ import print_function

import sys
import time
import argparse
import getpass
from threading import Thread, Condition
import thread

import minecraft.authentication as authentication
import minecraft.networking.connection as connection
import minecraft.networking.packets as packets

import mcstatus
import json_chat

KEEPALIVE_TIMEOUT_S = 20

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('addr',  metavar='HOST[:PORT]')
    parser.add_argument('uname', metavar='USERNAME')
    parser.add_argument('pword', metavar='PASSWORD', nargs='?')
    parser.add_argument('--offline', dest='offline', action='store_true')

    args = parser.parse_args()
    host, port = (
        (args.addr.rsplit(':', 1)[0], int(args.addr.rsplit(':', 1)[1]))
        if ':' in args.addr else (args.addr, None))
    offline = args.offline
    if args.pword is None and not offline:
        pword = getpass.getpass(
            'Enter password for %s, or leave blank for offline mode: '
            % args.uname) 
        if not pword: offline = True
    else:
        pword = args.pword

    connect(args.uname, pword, host, port, offline=offline)

def connect(uname, pword, host, port=None, offline=False):
    port = 25565 if port is None else port

    if offline:
        auth = authentication.AuthenticationToken('-', '-', '-')
        auth.profile.id_ = '-'
        auth.profile.name = uname
    else:
        auth = authentication.AuthenticationToken()
        auth.authenticate(uname, pword)

    conn = connection.Connection(host, port, auth)
    keepalive_cond = Condition()

    conn.register_packet_listener(h_join_game,
        packets.JoinGamePacket)
    conn.register_packet_listener(h_chat_message,
        packets.ChatMessagePacket)
    conn.register_packet_listener(lambda p: h_keepalive(keepalive_cond, p),
        packets.KeepAlivePacket)
    conn.register_packet_listener(h_disconnect,
        packets.DisconnectPacket, packets.DisconnectPacketPlayState)

    stdin = Thread(name='stdin', target=stdin_thread, args=(
        conn,))
    stdin.daemon = True

    timeout = Thread(name='timeout', target=timeout_thread, args=(
        keepalive_cond,))
    timeout.daemon = True

    conn.connect()
    stdin.start()
    timeout.start()
    main_thread(conn)
  
def h_join_game(packet):
    print('Connected to server.')

def h_chat_message(packet):
    print(json_chat.decode_string(packet.json_data))

def h_keepalive(keepalive_cond, packet):
    keepalive_cond.acquire()
    keepalive_cond.value = True
    keepalive_cond.notify_all()
    keepalive_cond.release()

def h_disconnect(packet):
    msg = json_chat.decode_string(packet.json_data)
    print('Disconnected from server: %s' % msg)
    thread.interrupt_main()

def main_thread(conn):
    try:
        while conn.networking_thread.is_alive():
            conn.networking_thread.join(0.1)
        print('Disconnected from server.')
    except KeyboardInterrupt as e:
        pass

def timeout_thread(keepalive_cond):
    while True:
        start = time.clock()
        keepalive_cond.acquire()
        keepalive_cond.value = False
        keepalive_cond.wait(KEEPALIVE_TIMEOUT_S)
        keepalive_cond.release()
        if not keepalive_cond.value: break

    print('Disconnected from server: timed out.')
    thread.interrupt_main()

def stdin_thread(conn):
    def send_chat(conn, text):
        packet = packets.ChatPacket()
        packet.message = text
        conn.write_packet(packet)
    while True:
        text = raw_input().decode('utf8')
        while len(text) > 100:
            send_chat(text[:97] + '...')
            text = '...' + text[97:]
        if text:
            send_chat(conn, text)

if __name__ == '__main__':
    main()
