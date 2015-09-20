#!/usr/bin/env python2.7

from __future__ import print_function

import sys
import time
import re
import argparse
import getpass
from threading import Thread, Condition, Lock
import thread
import imp

import minecraft.authentication as authentication
import minecraft.networking.connection as connection
import minecraft.networking.packets as packets

import mcstatus
import json_chat

KEEPALIVE_TIMEOUT_S = 30

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('addr',  metavar='HOST[:PORT]')
    parser.add_argument('uname', metavar='USERNAME')
    parser.add_argument('pword', metavar='PASSWORD', nargs='?')
    parser.add_argument('--offline', dest='offline', action='store_true')
    parser.add_argument('--plugins', dest='plugins', metavar='NAME', nargs='+')
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

    plugins = []
    for plugin in args.plugins or ():
        file, path, desc = imp.find_module(plugin, ['plugins'])
        plugins.append(imp.load_module(plugin, file, path, desc))

    connect(args.uname, pword, host, port, offline=offline, plugins=plugins)

def connect(uname, pword, host, port=None, offline=False, plugins=None):
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

    connected_cond = Condition()
    connected_cond.connected = False

    timeout = Thread(name='timeout', target=timeout_thread, 
        args=(keepalive_cond, connected_cond))
    timeout.daemon = True

    query = Thread(name='query', target=query_thread,
        args=(query_cond, host, port))
    query.daemon = True

    stdin = Thread(name='stdin', target=stdin_thread,
        args=(conn, query_cond, plist_cond, connected_cond))
    stdin.daemon = True

    conn.register_packet_listener(lambda p:
            h_join_game(timeout, connected_cond, p),
        packets.JoinGamePacket)
    conn.register_packet_listener(h_chat_message,
        packets.ChatMessagePacket)
    conn.register_packet_listener(lambda p:
            h_keepalive(keepalive_cond, p),
        packets.KeepAlivePacket)
    conn.register_packet_listener(lambda p:
            h_player_list_item(plist_cond, p),
        packets.PlayerListItemPacket)
    conn.register_packet_listener(lambda p:
            h_disconnect(connected_cond, p),
        packets.DisconnectPacket, packets.DisconnectPacketPlayState)

    for plugin in plugins or ():
        plugin.install(conn)

    conn.connect()
    query.start()
    stdin.start()

    make_query(query_cond, 'map')
    main_thread(connected_cond, conn)

def h_join_game(timeout_thread, connected_cond, packet):
    if not timeout_thread.is_alive():
        timeout_thread.start()
    with connected_cond:
        connected_cond.connected = True
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

def h_disconnect(connected_cond, packet):
    msg = json_chat.decode_string(packet.json_data)
    with connected_cond:
        pfile = sys.stdout if connected_cond.connected else sys.stderr
        fprint('Disconnected from server: %s' % msg, file=pfile)
    thread.interrupt_main()

def main_thread(connected_cond, conn):
    try:
        while conn.networking_thread.is_alive():
            conn.networking_thread.join(0.1)
        with connected_cond:
            pfile = sys.stdout if connected_cond.connected else sys.stderr
            fprint('Disconnected from server.', file=pfile)
    except KeyboardInterrupt as e:
        pass

def timeout_thread(keepalive_cond, connected_cond):
    while True:
        start = time.clock()
        with keepalive_cond:
            keepalive_cond.value = False
            keepalive_cond.wait(KEEPALIVE_TIMEOUT_S)
            if not keepalive_cond.value: break

    with connected_cond:
        pfile = sys.stdout if connected_cond.connected else sys.stderr
        fprint('Disconnected from server: timed out.', file=pfile)

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

def make_query(query_cond, query):
    with query_cond:
        query_cond.set.add(query)
        query_cond.notify_all()

def stdin_thread(conn, query_cond, plist_cond, connected_cond):
    def send_chat(conn, text):
        packet = packets.ChatPacket()
        packet.message = text
        conn.write_packet(packet)
    while True:
        text = raw_input().decode('utf8')        
        match = re.match(r'\?query\s+(\S+)\s*$', text)
        if match and match.group(1) == 'players':
            with connected_cond:
                if not connected_cond.connected:
                    continue
            with plist_cond:
                players = ' '.join(
                    json_chat.decode_string(p.display_name)
                        if p.display_name else p.name
                    for p in plist_cond.list.players_by_uuid.itervalues())
            fprint('!query success players %s' % players)
        elif match:
            make_query(query_cond, match.group(1))
        else:
            while len(text) > 100:
                send_chat(conn, text[:97] + '...')
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
