#!/usr/bin/env python2.7

from __future__ import print_function

import sys
import time
import re
import argparse
import getpass
from threading import Thread, Condition, Lock
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
        auth.join = lambda *a, **k: None
    else:
        auth = authentication.AuthenticationToken()
        auth.authenticate(uname, pword)

    conn = connection.Connection(host, port, auth)
    keepalive_cond = Condition()

    query_cond = Condition()
    query_cond.set = set()
    
    plist_cond = Condition()
    plist_cond.list = packets.PlayerListItemPacket.PlayerList()

    conn.register_packet_listener(h_join_game,
        packets.JoinGamePacket)
    conn.register_packet_listener(h_chat_message,
        packets.ChatMessagePacket)
    conn.register_packet_listener(lambda p:
            h_keepalive(keepalive_cond, p),
        packets.KeepAlivePacket)
    conn.register_packet_listener(lambda p:
            h_player_list_item(plist_cond, p),
        packets.PlayerListItemPacket)
    conn.register_packet_listener(h_disconnect,
        packets.DisconnectPacket, packets.DisconnectPacketPlayState)

    query = Thread(name='query', target=query_thread,
        args=(query_cond, host, port))
    query.daemon = True

    stdin = Thread(name='stdin', target=stdin_thread,
        args=(conn, query_cond, plist_cond))
    stdin.daemon = True

    timeout = Thread(name='timeout', target=timeout_thread, 
        args=(keepalive_cond,))
    timeout.daemon = True

    conn.connect()
    query.start()
    stdin.start()
    timeout.start()
    main_thread(conn)
  
def h_join_game(packet):
    fprint('Connected to server.')

def h_chat_message(packet):
    fprint(json_chat.decode_string(packet.json_data).encode('utf8'))

def h_keepalive(keepalive_cond, packet):
    with keepalive_cond:
        keepalive_cond.value = True
        keepalive_cond.notify_all()

def h_player_list_item(plist_cond, packet):
    with plist_cond:
        packet.apply(plist_cond.list)

def h_disconnect(packet):
    msg = json_chat.decode_string(packet.json_data)
    fprint('Disconnected from server: %s' % msg)
    thread.interrupt_main()

def main_thread(conn):
    try:
        while conn.networking_thread.is_alive():
            conn.networking_thread.join(0.1)
        fprint('Disconnected from server.')
    except KeyboardInterrupt as e:
        pass

def timeout_thread(keepalive_cond):
    while True:
        start = time.clock()
        with keepalive_cond:
            keepalive_cond.value = False
            keepalive_cond.wait(KEEPALIVE_TIMEOUT_S)
            if not keepalive_cond.value: break

    fprint('Disconnected from server: timed out.')
    thread.interrupt_main()

def query_thread(query_cond, host, port):
    while True:
        with query_cond:
            query_cond.wait()

        server = mcstatus.MinecraftServer(host, port)
        try:
            result = server.query()
        except Exception as e:
            result = e

        with query_cond:
            for query in query_cond.set:
                if isinstance(result, Exception):
                    fprint('!query failure %s %s' % (query, result))
                    continue
                elif query == 'map':
                    result = result.map
                elif query == 'players':
                    result = ' '.join(result.players.names)
                fprint('!query success %s %s' % (query, result))
            query_cond.set.clear()

def stdin_thread(conn, query_cond, plist_cond):
    def send_chat(conn, text):
        packet = packets.ChatPacket()
        packet.message = text
        conn.write_packet(packet)
    while True:
        text = raw_input().decode('utf8')        
        match = re.match(r'\?query\s+(\S+)\s*$', text)
        if match and match.group(1) == 'players':
            with plist_cond:
                players = ' '.join(
                    json_chat.decode_string(p.display_name)
                        if p.display_name else p.name
                    for p in plist_cond.list.players_by_uuid.itervalues())
            fprint('!query success players %s' % players)
        elif match:
            with query_cond:
                query_cond.set.add(match.group(1))
                query_cond.notify_all()
        else:
            while len(text) > 100:
                send_chat(text[:97] + '...')
                text = '...' + text[97:]
            if text:
                send_chat(conn, text)
    
    query_cond.acquire()
    sys.exit()

def fprint(*args, **kwds):
    print(*args, **kwds)
    kwds.get('file', sys.stdout).flush()

if __name__ == '__main__':
    main()
