#!/usr/bin/env python2.7

from __future__ import print_function

from threading import Thread, Lock, RLock, Condition
import threading
import sys
import time
import os
import os.path
import re
import argparse
import getpass
import socket
import json
import imp
import traceback
import functools

import minecraft.authentication as authentication
import minecraft.networking.connection as connection
import minecraft.networking.packets as packets
from minecraft.exceptions import YggdrasilError

import mcstatus
import json_chat

DEFAULT_PORT = 25565

KEEPALIVE_TIMEOUT_S = 30
STANDBY_QUERY_INTERVAL_S = 5

AUTH_TOKEN_PATH = os.path.join(
    os.path.dirname(__file__), 'var', 'authentication_token')
AUTH_RATE_LIMIT_MESSAGE = "[403] ForbiddenOperationException: 'Invalid credentials.'"
AUTH_ATTEMPTS_MAX = 6
AUTH_RETRY_DELAY_S = 10

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('addr',  metavar='HOST[:PORT]')
    parser.add_argument('uname', metavar='USERNAME')
    parser.add_argument('pword', metavar='PASSWORD', nargs='?')
    parser.add_argument('--offline', dest='offline', action='store_true')
    parser.add_argument('--standby', dest='standby', action='store_true')
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

    client = Client(
        uname=args.uname, pword=pword, host=host, port=port,
        offline=offline, standby=args.standby, plugins=plugins)

    client.start()
    try:
        while client.is_alive():
            client.join(0.1)
    except KeyboardInterrupt:
        client.interrupt()
        client.join(1)

class DisconnectReason(object): pass
class StandbyDisconnect(DisconnectReason): pass
class InterruptDisconnect(DisconnectReason): pass

class PacketHandler(object):
    def install(self, target):
        for method, types in self.get_packet_handlers():
            target.register_packet_listener(
                functools.partial(method, self), *types)

    @classmethod
    def get_packet_handlers(cls):
        if not hasattr(cls, 'packet_handlers'):
            cls.packet_handlers = []
        return cls.packet_handlers        

    @classmethod
    def handle(cls, *types):
        def d_handle(method):
            cls.get_packet_handlers().append((method, types))
            return method
        return d_handle

class Client(Thread, PacketHandler):
    def __init__(
        self, host, port=None, standby=False, plugins=None, *args, **kwds
    ):
        super(Client, self).__init__()
        self.daemon = True
        self.name = 'Client'
        self.standby = standby

        self.query = Query(host=host, port=port)

        plugins = (self,) + tuple(plugins or ())
        self.connection = Connection(
            host=host, port=port, plugins=plugins, *args, **kwds)

        self.rlock = RLock()
        self.exit_cond = Condition(self.rlock)
        self.player_list_cond = Condition(self.rlock)
        self.players = None
        self.reported_joined_players = set()
        self.reported_left_players = set()

    def run(self):
        targets = (
            self.run_player_list,
            self.run_read_input,
        )
        if self.standby:
            targets = (
                self.run_standby_query,
                self.run_standby_connect,
            ) + targets
        else:
            targets = (
                self.run_direct,
            ) + targets

        with self.rlock:
            for target in targets:
                thread = Thread(
                    target=target, name='Client.'+target.__name__)
                thread.daemon = True
                thread.start()

            self.serve_query('map')
            self.exit_cond.wait()

    def interrupt(self):
        with self.rlock:
            self.connection.ensure_disconnected(InterruptDisconnect())
            self.exit_cond.notify_all()

    def run_read_input(self):
        while True:
            text = raw_input().decode('utf8')
            match = re.match(r'\?query\s+(\S+)\s*$', text)
            if match:
                self.serve_query(match.group(1))
            else:
                self.connection.chat(text)

    def serve_query(self, query):
        def h_result(success, result):
            with self.rlock:
                fprint('!query %s %s %s' % (
                    'success' if success else 'failure', query, result))
        if query == 'players':
            with self.rlock:
                if self.players is not None:
                    h_result(True, ' '.join(sorted(self.players)))
                else:
                    h_result(True, '')
        elif query == 'agent':
            with self.connection.rlock:
                if self.connection.profile_name is not None:
                    h_result(True, self.connection.profile_name)
                else:
                    h_result(False, 'unknown')
        else:
            self._serve_query(query, h_result)

    def _serve_query(self, query, h_result):
        def _h_result(success, result):
            if not success:
                h_result(False, result)
            elif query not in result.raw:
                h_result(False, '"%s" not present in query response.' % query)
            else:
                h_result(True, result.raw[query])
        self.query.query_async(_h_result)

    def run_standby_connect(self):
        with self.connection.rlock:
            while True:
                self.connection.disconnect_cond.wait()              
                reason = self.connection.disconnect_reason

                if isinstance(reason, StandbyDisconnect): continue
                if isinstance(reason, InterruptDisconnect): break
                fprint('Disconnected from server: %s' % reason)

                with self.rlock:
                    self.exit_cond.notify_all()
                break

    def run_standby_query(self):
        while True:
            time.sleep(STANDBY_QUERY_INTERVAL_S)

            try:
                result = self.query.query()
            except Exception as e:
                traceback.print_exc()
                with self.rlock:
                    if self.players is not None:
                        fprint('Failed to contact server: %s' % e)
                    self.exit_cond.notify_all()
                    return

            new_players = set(result.players.names)
            if new_players - {self.connection.profile_name}:
                self.connection.ensure_connecting()
            else:
                with self.rlock:
                    if self.players is None:
                        fprint('Connected to server in standby mode.')
                self.connection.ensure_disconnected(StandbyDisconnect())

            with self.connection.rlock:
                if not self.connection.disconnected:
                    self.connection.disconnect_cond.wait()
                    reason = self.connection.disconnect_reason
                    if isinstance(reason, StandbyDisconnect):
                        continue
                    else:
                        break                    

            if not new_players or self.players is not None:
                self.set_players(new_players)

    def run_direct(self):
        with self.connection.rlock:
            self.connection.connect()
            self.connection.disconnect_cond.wait()
            reason = self.connection.disconnect_reason
        if isinstance(reason, InterruptDisconnect): return
        with self.rlock:
            if self.players is not None:
                fprint('Disconnected from server: %s' % reason)
            self.exit_cond.notify_all()

    def run_player_list(self):
        with self.rlock:
            while True:
                self.player_list_cond.wait()
                clock = time.clock()
                end = clock + 0.1
                while clock < end:
                    self.player_list_cond.wait(end - clock + 0.01)
                    clock = time.clock()
                self.update_player_list()

    def update_player_list(self):
        with self.connection.rlock:
            if self.connection.player_list is None: return
            new_players = set(
                json_chat.decode_string(p.display_name)
                if p.display_name else p.name for p in
                self.connection.player_list.players_by_uuid.itervalues())
            self.set_players(new_players)

    def set_players(self, new_players):
        with self.rlock:
            with self.connection.rlock:
                profile_name = self.connection.profile_name

            if self.players is not None:
                for added_player in new_players - self.players:
                    if (added_player not in self.reported_joined_players
                    and added_player != profile_name):
                        fprint(json_chat.decode_struct({
                            'translate': 'multiplayer.player.joined',
                            'using': [added_player]}))
                    self.reported_joined_players.add(added_player)
                    self.reported_left_players.discard(added_player)
                for removed_player in self.players - new_players:
                    if (removed_player not in self.reported_left_players
                    and removed_player != profile_name):
                        fprint(json_chat.decode_struct({
                            'translate': 'multiplayer.player.left',
                            'using': [removed_player]}))        
                    self.reported_left_players.add(removed_player)
                    self.reported_joined_players.discard(removed_player)

            if self.standby and not (new_players - {profile_name}):
                self.connection.ensure_disconnected(StandbyDisconnect())

            self.players = new_players

@Client.handle(packets.JoinGamePacket)
def h_join_game(self, packet):
    with self.rlock:
        if self.players is None:
            fprint('Connected to server.')

@Client.handle(packets.ChatMessagePacket)
def h_chat_message(self, packet):
    with self.rlock:
        data = json.loads(packet.json_data)
        using = data.get('using') or data.get('with')
        omit_message = False

        if data.get('translate') == 'multiplayer.player.joined':
            player = json_chat.decode_struct(using[0])
            if player in self.reported_joined_players:
                omit_message = True
            else:
                self.reported_joined_players.add(player)
                self.reported_left_players.discard(player)
            new_players = self.players | {player}
        elif data.get('translate') == 'multiplayer.player.left':
            player = json_chat.decode_struct(using[0])
            if player in self.reported_left_players:
                omit_message = True
            else:
                self.reported_left_players.add(player)
                self.reported_joined_players.discard(player)
            new_players = self.players - {player}
        else:
            player = None
            new_players = None

        if data.get('translate').startswith('chat.type.'):
            with self.connection.rlock:
                player = json_chat.decode_struct(using[0])
                if player == self.connection.profile_name:
                    omit_message = True

        fprint(json_chat.decode_string(packet.json_data).encode('utf8'),
            file=sys.stderr if omit_message else sys.stdout)

        if new_players is not None:
            self.set_players(new_players)

@Client.handle(packets.PlayerListItemPacket)
def h_player_list_item(self, packet):
    with self.rlock:
        self.player_list_cond.notify_all()

class Connection(PacketHandler):
    def __init__(
        self, uname, pword, host, port=None, offline=False, plugins=None
    ):
        super(Connection, self).__init__()
        self.uname = uname
        self.pword = pword
        self.host = host
        self.port = port or DEFAULT_PORT
        self.offline = offline
        self.plugins = plugins

        self.rlock = RLock()
        self.connection = None
        self.player_list = None
        self.profile_name = None
        self.disconnect_cond = Condition(self.rlock)
        self.disconnect_reason = None
        self.fully_connected = False
        self.disconnected = True

        self.auth_token = None

    def ensure_connecting(self):
        with self.rlock:
            if self.disconnected:
                self.connect()

    def ensure_disconnected(self, reason=None):
        with self.rlock:
            if not self.disconnected:
                self.disconnect(reason)

    def connect(self):
        with self.rlock:
            assert self.disconnected
            self.disconnected = False
            self.profile_name = None

        thread = Thread(
            target=self.run_connection, name='Connection.run_connection')
        thread.daemon = True
        thread.start()   
        
    def disconnect(self, reason=None):
        with self.rlock:
            assert not self.disconnected

            if self.connection is not None:
                self.connection.packet_listeners[:] = []
                sock = self.connection.socket
                if hasattr(sock, 'actual_socket'):
                    sock = sock.actual_socket
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                self.connection = None

            self.player_list = None
            self.fully_connected = False
            self.disconnected = True
            self.disconnect_reason = reason
            self.disconnect_cond.notify_all()

    def chat(self, text):
        with self.rlock:
            if self.fully_connected:
                while len(text) > 100:
                    self._chat(text[:97] + '...')
                    text = '...' + text[97:]
                if text:
                    self._chat(text)
            else:
                fprint('Warning: message not sent, as not connected to server.',
                    file=sys.stderr)

    def _chat(self, text):
        packet = packets.ChatPacket()
        packet.message = text
        self.connection.write_packet(packet)

    def run_connection(self):
        try:
            auth = self.authenticate()
        except Exception as e:
            traceback.print_exc()
            return self.disconnect(e)

        with self.rlock:
            self.profile_name = auth.profile.name
            conn = connection.Connection(self.host, self.port, auth)
            for plugin in (self,) + tuple(self.plugins or ()):
                plugin.install(conn)
            self.connection = conn
            self.keep_alive = True

        try:
            conn.connect()
        except BaseException as e:
            traceback.print_exc()
            return self.disconnect(e)

        while conn.networking_thread.is_alive():
            with self.rlock:
                if not self.keep_alive:
                    if conn is self.connection:
                        self.disconnect('timed out (%ss).' % KEEPALIVE_TIMEOUT_S)
                    return
                self.keep_alive = False
            conn.networking_thread.join(KEEPALIVE_TIMEOUT_S)

        with self.rlock:
            if conn is self.connection:
                reason = getattr(conn, 'exception', 'unknown error.')
                if isinstance(reason, BaseException):
                    traceback.print_exception(*reason.exc_info)
                self.disconnect(reason)

    def authenticate(self):
        for i in range(AUTH_ATTEMPTS_MAX):
            try:
                return self._authenticate()
            except YggdrasilError as e:
                self.auth_token = None
                if e.message == AUTH_RATE_LIMIT_MESSAGE:
                    fprint('Authentication rate-limited; retrying in '
                        '%s seconds (%d/%d).'
                        % (AUTH_RETRY_DELAY_S, i+1, AUTH_ATTEMPTS_MAX),
                        file=sys.stderr)
                    time.sleep(AUTH_RETRY_DELAY_S)
                else:
                    raise
        raise Exception(
            'Authentication abandoned after being rate-limited %d times.'
                % AUTH_ATTEMPTS_MAX)

    def _authenticate(self):
        with self.rlock:
            if self.auth_token is None and self.offline:
                self.auth_token = authentication.AuthenticationToken(
                    '-', '-', '-')
                self.auth_token.profile.id_ = '-'
                self.auth_token.profile.name = self.uname
                self.auth_token.join = lambda *a, **k: None

            if self.auth_token is None and os.path.exists(AUTH_TOKEN_PATH):
                try:
                    with open(AUTH_TOKEN_PATH) as file:
                        saved_token = json.load(file)
                except Exception as e:
                    traceback.print_exc()
                    saved_token = None

            if (self.auth_token is None and isinstance(saved_token, dict)
            and saved_token.get('username' == self.uname)
            and 'access_token' in saved_token and 'client_token' in saved_token):
                self.auth_token = authentication.AuthenticationToken(
                    access_token = saved_token['access_token'],
                    client_token = saved_token['client_token'])
                
                if not self.auth_token.refresh():
                    fprint('Warning: %s is not valid. Discarding.'
                        % AUTH_TOKEN_PATH, file=sys.stderr)
                    self.auth_token = None

            if self.auth_token is None:
                self.auth_token = authentication.AuthenticationToken()
                self.auth_token.authenticate(self.uname, self.pword)

            if not self.offline:
                try:
                    with open(AUTH_TOKEN_PATH, 'w') as file:
                        json.dump({
                            'username':     self.uname,
                            'access_token': self.auth_token.access_token,
                            'client_token': self.auth_token.client_token
                        }, file)
                except IOError as e:
                    traceback.print_exc()

            return self.auth_token

@Connection.handle(packets.JoinGamePacket)
def h_join_game(self, packet):
    with self.rlock:
        self.fully_connected = True

@Connection.handle(packets.PlayerListItemPacket)
def h_player_list_item(self, packet):
    with self.rlock:
        if self.player_list is None:
            self.player_list = packets.PlayerListItemPacket.PlayerList()
        packet.apply(self.player_list)

@Connection.handle(packets.KeepAlivePacket)
def h_keep_alive(self, packet):
    with self.rlock:
        self.keep_alive = True

@Connection.handle(packets.DisconnectPacket)
def h_disconnect(self, packet):
    reason = json_chat.decode_string(packet.json_data)
    self.ensure_disconnect(reason)

class Query(object):
    def __init__(self, host, port=DEFAULT_PORT):
        self.rlock = RLock()
        self.server = mcstatus.MinecraftServer(host, port or DEFAULT_PORT)
        self.complete_cond = Condition(self.rlock)
        self.pending = False
        self.result = None
        self.waiting = []

    def query(self):
        with self.rlock:
            self.start_query_async()
            self.complete_cond.wait()
            if isinstance(self.result, Exception):
                ty, ex, tb = self.result.exc_info
                raise ty, ex, tb
            else:
                return self.result

    def query_async(self, h_result):
        with self.rlock:
            self.waiting.append(h_result)
            self.start_query_async()

    def start_query_async(self):
        with self.rlock:
            if not self.pending:
                thread = Thread(target=self.start_query, name='Query')
                thread.daemon = True
                thread.start()

    def start_query(self):
        with self.rlock:
            self.pending = True
        try:
            result = self.server.query()
            success = True
        except Exception as e:
            e.exc_info = sys.exc_info()
            result = e
            success = False
        with self.rlock:
            self.result = result
            self.pending = False
            self.complete_cond.notify_all()
            for h_result in self.waiting:
                h_result(success, result)
            del self.waiting[:]

def fprint(*args, **kwds):
    print(*args, **kwds)
    kwds.get('file', sys.stdout).flush()

if __name__ == '__main__':
    main()
