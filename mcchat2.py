#!/usr/bin/env python

from __future__ import print_function

from threading import Thread, Lock, RLock, Condition
from functools import *
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
import itertools
import errno

from future.utils import raise_
from builtins import input

import minecraft.authentication as authentication
import minecraft.networking.connection as connection
import minecraft.networking.packets as packets
from minecraft.exceptions import YggdrasilError

import mcstatus
import json_chat

DEFAULT_PORT = 25565

KEEPALIVE_TIMEOUT_S        = 30
STANDBY_QUERY_INTERVAL_S   = 5
PREVENT_TIMEOUT_INTERVAL_S = 60
RECONNECT_DELAY_S          = 5

QUERY_ATTEMPTS          = 3
QUERY_RETRY_INTERVAL_S  = 5
QUERY_TIMEOUT_S         = 60
QUERY_TIMEOUT_ATTEMPTS  = 10

AUTH_RATE_LIMIT_MESSAGE = "[403] ForbiddenOperationException: 'Invalid credentials.'"
AUTH_ATTEMPTS_MAX = 6
AUTH_RETRY_DELAY_S = 10

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        'addr',  metavar='HOST[:PORT]',
        help='-- The hostname or IP address of the Minecraft server to which to'
        'connect, and an optional port number defaulting to %d.' % DEFAULT_PORT)
    parser.add_argument(
        'uname', metavar='USERNAME',
        help='-- If connecting to a server in online mode, the Mojang account name '
        'to authenticate to - usually an email address; otherwise, the display name '
        'to use in an offline server.')
    parser.add_argument(
        'pword', metavar='PASSWORD', nargs='?',
        help='-- If connecting to a server in online mode, the password of the Mojang '
        'account given by USERNAME. If not given on the command line, the user is '
        'prompted to enter the password on the terminal without echoing.')
    parser.add_argument(
        '--password-file', dest='password_file', metavar='FILE',
        help='-- Read the password for USERNAME from a text file.')
    parser.add_argument(
        '--help', action='help',
        help='-- Display information about the command-line arguments of this '
        'program.')
    parser.add_argument(
        '--offline', dest='offline', action='store_true',
        help='-- Connect to a server in offline mode, i.e. without using Mojang\'s '
        'authentication server. Standard Mojang servers must be configured with '
        '"online-mode=false" in the "Server.properties" file.')
    parser.add_argument(
        '--standby', dest='standby', action='store_true',
        help='-- Connect in "standby mode": periodically issue status queries to the '
        'server to determine the number of users online, connect only when there '
        'are users online, and disconnect when all other users leave. This can be '
        'useful to reduce idle resource usage on the server.')
    parser.add_argument(
        '--quiet-start', dest='quiet_start', action='store_true',
        help='-- When connecting in standby mode, print the connection message to '
        'standard error instead of standard output. This can be useful to restart '
        'the client without generating unnecessary noise.')
    parser.add_argument(
        '--protocol', dest='version', metavar='VERSION',
        help='-- The protocol version number to use when initially attempting to '
        'join the server. If this is the incorrect version, the client will attempt '
        'other version numbers until the correct version is found or all supported '
        'versions are exhausted. This option defaults to the highest supported '
        'version, and its effect is only to speed up the negotiation process.')
    parser.add_argument(
        '--prevent-idle-timeout', dest='prevent_timeout', action='store_true',
        help='-- On servers with "player-idle-timeout" set to a nonzero value, '
        'sends periodic activity to prevent the client from being kicked.')
    parser.add_argument(
        '--auto-query', dest='auto_query', action='store_true',
        help='-- Automatically issue "?query map" and "?query agent" at appropriate'
        ' times. See README.md for a full explanation.')
    parser.add_argument(
        '--plugins', dest='plugins', metavar='NAME[,NAME...]',
        help='-- A comma-separated list of plugin modules to install on the client. '
        'A plugin is a Python module in the "plugins" directory with a top-level '
        'function install(conn) which takes a minecraft.networking.Connection '
        'object which is called by the client each time it connects to the server.')
    parser.add_argument(
        '--no-timeout', dest='no_timeout', action='store_true',
        help='-- Disable the default behaviour of disconnecting when no keep-alive '
        'message has been received from the server for %s seconds. Mainly useful '
        'for debugging.' % KEEPALIVE_TIMEOUT_S)
    parser.add_argument(
        '--no-input', dest='no_input', action='store_true',
        help='-- Do not read any messages from standard input. Mainly useful for '
        'debugging.')
    parser.add_argument(
        '--show-packets', dest='show_packets', action='store_true',
        help='-- Print to standard error all sent packets and all received packets '
        'of known type. Mainly useful for debugging.')
    args = parser.parse_args()

    host, port = (
        (args.addr.rsplit(':', 1)[0], int(args.addr.rsplit(':', 1)[1]))
        if ':' in args.addr else (args.addr, None))
    offline = args.offline
    if args.password_file is not None:
        with open(args.password_file) as file:
            pword = file.read().strip()
    elif args.pword is None and not offline:
        pword = getpass.getpass(
            'Enter password for %s, or leave blank for offline mode: '
            % args.uname) 
        if not pword: offline = True
    else:
        pword = args.pword

    plugins = []
    if args.plugins:
        for plugin in args.plugins.split(','):
            file, path, desc = imp.find_module(plugin, ['plugins'])
            plugins.append(imp.load_module(plugin, file, path, desc))

    try: version = int(args.version)
    except ValueError: version = args.version
    except TypeError: version = args.version

    client = Client(
        uname           = args.uname,
        pword           = pword,
        host            = host,
        port            = port,
        offline         = offline,
        standby         = args.standby,
        quiet_start     = args.quiet_start,
        version         = version,
        prevent_timeout = args.prevent_timeout,
        auto_query      = args.auto_query,
        plugins         = plugins,
        no_timeout      = args.no_timeout,
        no_input        = args.no_input,
        show_packets    = args.show_packets)

    client.start()
    try:
        while client.is_alive():
            client.join(0.1)
    except KeyboardInterrupt:
        client.interrupt()
        client.join(1)

    if isinstance(client.exit_reason, ExitReason):
        sys.exit(client.exit_reason.exit_code)

class ExitReason(object):
    def __init__(self, cause=None, code=None):
        super(ExitReason, self).__init__()
        self.cause = cause
        self.exit_code = code
    def __str__(self):
        if self.cause is None:
            return super(ExitReason, self).__str__()
        else:
            return str(self.cause)

# A SilentExit does not generate any output.
class SilentExit(ExitReason):
    pass

# A QuietExit generates all output on stderr rather than stdout.
class QuietExit(ExitReason):
    pass

# A PermanentExit causes the client program to terminate.
class PermanentExit(ExitReason):
    pass

class StandbyExit(SilentExit):
    pass

class UserCollision(PermanentExit):
    def __init__(self, cause=None, *args, **kwds):
        super(UserCollision, self).__init__(
            cause or 'user collision.', *args, **kwds)

class ManualExit(PermanentExit):
    def __init__(self, cause=None, *args, **kwds):
        super(ManualExit, self).__init__(
            cause or 'manually closed.', *args, **kwds)

class QuietManualExit(QuietExit, ManualExit):
    pass

class PacketHandler(object):
    def __init__(self):
        super(PacketHandler, self).__init__()
        self.inst_packet_handlers = []

    def install(self, target):
        handlers = self.inst_packet_handlers + self.get_packet_handlers()
        for method, types in handlers:
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

    def inst_handle(self, *types):
        def d_inst_handle(method):
            self.inst_packet_handlers.append((method, types))
            return method
        return d_inst_handle

class Client(PacketHandler, Thread):
    def __init__(
        self, host, port=None, standby=False, plugins=None,
        auto_query=False, quiet_start=False, no_input=False,
        *args, **kwds
    ):
        super(Client, self).__init__()
        self.daemon = True
        self.name = 'Client'
        self.standby = standby
        self.auto_query = auto_query
        self.quiet_start = quiet_start
        self.no_input = no_input

        self.gamespy_query = GameSpyQuery(host=host, port=port)
        if self.standby:
            self.status_query = StatusQuery(host=host, port=port)

        plugins = (self,) + tuple(plugins or ())
        self.connection = Connection(
            host=host, port=port, plugins=plugins, *args, **kwds)

        self.rlock = RLock()
        self.exit_cond = Condition(self.rlock)
        self.exit_reason = None
        self.player_list_cond = Condition(self.rlock)
        self.players = None
        self.reported_joined_players = set()
        self.reported_left_players = set()
        self.reconnecting = False
        self.connecting = True
        self.pending_queries = set()

    def run(self):
        targets = (
            self.run_player_list,
        )
        if not self.no_input:
            targets = (
                self.run_read_input,
            ) + targets
        if self.standby:
            targets = (
                self.run_standby,
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

            if self.auto_query:
                self.serve_query('map')
            self.exit_cond.wait()

    def interrupt(self):
        self.exit(ManualExit())

    def run_read_input(self):
        while True:
            text = input()
            if hasattr(text, 'decode'): text = text.decode('utf8')

            match = re.match(r'\?query\s+(\S+)\s*$', text)
            if match:
                self.serve_query(match.group(1))
                continue

            match = re.match(r'\?exit\s*(.*)', text)
            if match:
                msg, quiet, code = match.group(1), False, 0
                while msg.startswith('--'):
                    match = re.match(r'--(?P<key>[^\s=]*)(=(?P<val>\S+))?\s*(?P<rem>.*)', msg)
                    if match.group('key') == 'quiet' and match.group('val') is None:
                        quiet = True
                    elif match.group('key') == 'code' and match.group('val') is not None \
                    and re.match(r'\d+$', match.group('val')):
                        code = int(match.group('val'))
                    else:
                        fprint('Error: invalid argument: "%s".' % match.group(),
                            file=sys.stderr)
                        continue
                    msg = match.group('rem')
                self.exit(
                    (QuietManualExit if quiet else ManualExit)(msg.strip(), code=code))
                continue

            self.connection.chat(text)

    def exit(self, reason):
        was_connected = self.connection.ensure_disconnected(reason)
        if not isinstance(reason, PermanentExit): return
        with self.rlock:
            if not (was_connected or isinstance(reason, SilentExit)):
                fprint('Disconnected: %s' % reason,
                    file = sys.stderr if isinstance(reason, QuietExit)
                      else sys.stdout)
            self.exit_reason = reason
            self.exit_cond.notify_all()

    def serve_query(self, query):
        with self.rlock:
            if query in self.pending_queries:
                return
            self.pending_queries.add(query)
        def h_result(success, result):
            with self.rlock:
                self.pending_queries.remove(query)
                fprint('!query %s %s %s' % (
                    'success' if success else 'failure', query, result))
        if query == 'players':
            with self.rlock:
                if self.players is not None:
                    h_result(True, ' '.join(sorted(self.players)))
                else:
                    h_result(False, 'No contact with server.')
        elif query == 'agent':
            with self.connection.rlock:
                if self.connection.profile_name is not None:
                    h_result(True, self.connection.profile_name)
                else:
                    h_result(False, 'Unknown')
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
        self.gamespy_query.query_async(_h_result)

    def run_standby(self):
        fprint('Connecting in standby mode...',
            file=sys.stderr)
        while True:
            try:
                result = self.status_query.query()
            except Exception as e:
                if not isinstance(e, IOError):
                    traceback.print_exc()
                with self.rlock:
                    fprint('Failed to contact server: %s' % e,
                        file = sys.stderr if self.reconnecting else sys.stdout)
                    self.players = None
                    self.connecting = True
                    self.reconnecting = True
                    time.sleep(RECONNECT_DELAY_S)
                    continue

            sample_players = { p.name for p in result.players.sample or [] }
            if not (sample_players - {self.connection.profile_name}):
                with self.rlock:
                    if self.connecting:
                        fprint('Connected to server in standby mode.',
                            file = sys.stderr if self.quiet_start
                                   and not self.reconnecting else sys.stdout)
                        if self.reconnecting and self.auto_query:
                            self.serve_query('map')
                        self.connecting = False
                        self.reconnecting = False
                self.set_players(sample_players)
                time.sleep(STANDBY_QUERY_INTERVAL_S)
                continue

            self.connection.connect()
            with self.connection.rlock:
                self.connection.disconnect_cond.wait()
                reason = self.connection.disconnect_reason

            with self.rlock:
                if not isinstance(reason, SilentExit):
                    message = 'Failed to connect to server' if self.connecting \
                         else 'Disconnected from server'
                    fprint('%s: %s' % (message, reason),
                        file=sys.stderr if self.reconnecting else sys.stdout)
                if isinstance(reason, PermanentExit):
                    self.exit_reason = reason
                    self.exit_cond.notify_all()
                    break
                elif not isinstance(reason, StandbyExit):
                    self.players = None
                    self.connecting = True
                    self.reconnecting = True
            
            if isinstance(reason, StandbyExit):
                time.sleep(STANDBY_QUERY_INTERVAL_S)
            else:
                time.sleep(RECONNECT_DELAY_S)

    def run_direct(self):
        fprint('Connecting...', file=sys.stderr)
        while True:
            with self.connection.rlock:
                self.connection.connect()
                self.connection.disconnect_cond.wait()
                reason = self.connection.disconnect_reason
            with self.rlock:
                if not isinstance(reason, SilentExit):
                    message = 'Failed to connect to server' if self.connecting \
                         else 'Disconnected from server'
                    fprint('%s: %s' % (message, reason),
                        file=sys.stderr if self.reconnecting else sys.stdout)
                if isinstance(reason, PermanentExit):
                    self.exit_reason = reason
                    self.exit_cond.notify_all()
                    break
                self.reconnecting = True
                self.connecting = True
            time.sleep(RECONNECT_DELAY_S)

    def run_player_list(self):
        with self.rlock:
            while True:
                self.player_list_cond.wait()
                clock = time.time()
                end = clock + 0.1
                while clock < end:
                    self.player_list_cond.wait(end - clock + 0.01)
                    clock = time.time()
                self.update_player_list()

    def update_player_list(self):
        with self.connection.rlock:
            if self.connection.player_list is None: return
            new_players = set(
                json_chat.decode_string(p.display_name)
                if p.display_name else p.name for p in
                self.connection.player_list.players_by_uuid.values())
        with self.rlock:
            if self.players is None:
                self.list_players(new_players)
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
                self.connection.ensure_disconnected(StandbyExit())

            self.players = new_players

    def list_players(self, players):
        players_str = ', '.join(sorted(players)) if players else '(none)'
        with self.rlock:
            fprint('Players online: %s.' % players_str)

@Client.handle(packets.JoinGamePacket)
def h_join_game(self, packet):
    with self.rlock:
        if self.connecting:
            fprint('Connected to server.')
            if self.reconnecting and self.auto_query:
                self.serve_query('map')
            if self.players is not None:
                self.list_players(self.players)
        self.connecting = False
        self.reconnecting = False
    if self.auto_query:
        self.serve_query('agent')

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

        chat_string = json_chat.decode_string(packet.json_data)
        if type(chat_string) is not str:
            chat_string = chat_string.encode('utf8')
        fprint(chat_string, file=sys.stderr if omit_message else sys.stdout)

        if new_players is not None:
            self.set_players(new_players)

@Client.handle(packets.PlayerListItemPacket)
def h_player_list_item(self, packet):
    with self.rlock:
        self.player_list_cond.notify_all()

class Connection(PacketHandler):
    def __init__(
        self, uname, pword, host, port=None, offline=False, version=None,
        prevent_timeout=False, no_timeout=False, show_packets=False,
        plugins=None,
    ):
        super(Connection, self).__init__()
        self.uname = uname
        self.pword = pword
        self.host = host
        self.port = port or DEFAULT_PORT
        self.offline = offline
        self.version = version
        self.prevent_timeout = prevent_timeout
        self.no_timeout = no_timeout
        self.show_packets = show_packets
        self.plugins = plugins

        self.rlock = RLock()
        self.connection = None
        self.player_list = None
        self.profile_name = None
        self.disconnect_cond = Condition(self.rlock)
        self.disconnect_reason = None
        self.fully_connected = False
        self.position = None
        self.disconnected = True

        self.auth_token = None

        if self.show_packets:
            self.inst_handle(packets.Packet)(self.show_recv_packet)

    def ensure_connecting(self):
        with self.rlock:
            if self.disconnected:
                self.connect()
                return True
        return False

    def ensure_disconnected(self, reason=None):
        with self.rlock:
            if not self.disconnected:
                self.disconnect(reason)
                return True
        return False

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
                try: sock.shutdown(socket.SHUT_RDWR)
                except IOError: pass
                try: sock.close()
                except IOError: pass
                self.connection = None

            self.player_list = None
            self.fully_connected = False
            self.position = None
            self.disconnected = True
            self.disconnect_reason = reason
            self.disconnect_cond.notify_all()

    def chat(self, text):
        with self.rlock:
            if self.fully_connected:
                max_length = packets.ChatPacket.get_max_length(
                    self.connection.context)
                while len(text) > max_length:
                    self._chat(text[:max_length])
                    text = '...' + text[max_length:]
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
            if not isinstance(e, IOError):
                traceback.print_exc()
            return self.disconnect(e)

        with self.rlock:
            self.profile_name = auth.profile.name
            conn = connection.Connection(
                self.host, self.port, auth, initial_version=self.version)
            for plugin in (self,) + tuple(self.plugins or ()):
                plugin.install(conn)
            if self.show_packets:
                conn.write_packet = partial(
                    self.show_send_packet, cont=conn.write_packet)
            self.connection = conn
            self.keep_alive = True

        try:
            conn.connect()
        except BaseException as e:
            if not isinstance(e, IOError):
                traceback.print_exc()
            return self.disconnect(e)

        if self.prevent_timeout:
            thread = Thread(
                target = self.run_prevent_timeout,
                name   = 'Connection.run_prevent_timeout')
            thread.daemon = True
            thread.start()

        while conn.networking_thread.is_alive():
            with self.rlock:
                if not self.keep_alive:
                    if conn is self.connection:
                        self.disconnect('Timed out (%ss).' % KEEPALIVE_TIMEOUT_S)
                    return
                self.keep_alive = False
            conn.networking_thread.join(
                None if self.no_timeout else KEEPALIVE_TIMEOUT_S)

        with self.rlock:
            if conn is self.connection:
                reason = getattr(conn, 'exception', 'Unknown error.')
                if isinstance(reason, BaseException) \
                and not isinstance(reason, IOError):
                    traceback.print_exception(*reason.exc_info)
                self.disconnect(reason)

    def run_prevent_timeout(self):
        with self.rlock:
            while True:
                self.disconnect_cond.wait(PREVENT_TIMEOUT_INTERVAL_S)
                if self.disconnected: break
                packet = packets.AnimationPacketServerbound(
                    hand = packets.AnimationPacketServerbound.HAND_MAIN)
                self.connection.write_packet(packet)

    def authenticate(self):
        for i in range(AUTH_ATTEMPTS_MAX):
            try:
                return self._authenticate()
            except YggdrasilError as e:
                self.auth_token = None
                if e.args == (AUTH_RATE_LIMIT_MESSAGE,):
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
            elif self.auth_token is None:
                self.auth_token = authentication.AuthenticationToken()
                self.auth_token.authenticate(self.uname, self.pword)
            elif not self.offline:
                self.auth_token.refresh()
            return self.auth_token

    @staticmethod
    def show_recv_packet(self, packet):
        if type(packet) is not packets.Packet:
            fprint('> %s' % packet, file=sys.stderr)

    def show_send_packet(self, packet, *args, **kwds):
        _write = packet.write
        def write(*args, **kwds):
            fprint('< %s' % packet, file=sys.stderr)
            return _write(*args, **kwds)
        packet.write = write
        return kwds.pop('cont')(packet, *args, **kwds)

@Connection.handle(packets.LoginSuccessPacket)
def h_login_success(self, packet):
    with self.rlock:
        self.version = packet.context.protocol_version

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

@Connection.handle(packets.DisconnectPacket, packets.DisconnectPacketPlayState)
def h_disconnect(self, packet):
    reason = json_chat.decode_string(packet.json_data)
    if reason == 'You logged in from another location':
        reason = UserCollision(reason)
    self.ensure_disconnected(reason)

@Connection.handle(packets.PlayerPositionAndLookPacket)
def h_player_position_and_look(self, packet):
    if self.position is None:
        self.position = packets.PlayerPositionAndLookPacket.PositionAndLook(
            x=0, y=0, z=0, yaw=0, pitch=0)
    packet.apply(self.position)

class AbstractQuery(object):
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
                raise_(*self.result.exc_info)
            else:
                return self.result

    def query_async(self, h_result):
        with self.rlock:
            self.waiting.append(h_result)
            self.start_query_async()

    def start_query_async(self):
        with self.rlock:
            if not self.pending:
                thread = Thread(target=self.start_query, name=type(self).__name__)
                thread.daemon = True
                thread.start()

    def start_query(self):
        with self.rlock:
            self.pending = True
        try:
            for tries in itertools.count(QUERY_ATTEMPTS):
                try:
                    result = self.raw_query()
                    success = True
                    break
                except Exception as e:
                    timed_out = (isinstance(e, socket.error)
                        and e.errno == errno.ETIMEDOUT)
                    if timed_out and tries < QUERY_TIMEOUT_ATTEMPTS \
                    or not timed_out and tries < QUERY_ATTEMPTS:
                        fprint('[%s %d/%d] %s' % (
                            type(self).__name__, tries, QUERY_ATTEMPTS, e), file=sys.stderr)
                        if not timed_out:
                            time.sleep(QUERY_RETRY_INTERVAL_S)
                    elif timed_out:
                        raise Exception('Timed out (%ss, %s attempts).' % (
                            QUERY_TIMEOUT_S, tries+1))
                    else:
                        raise
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

    def raw_query(self):
        raise NotImplementedError('Must be overridden by a base class.')

class GameSpyQuery(AbstractQuery):
    def raw_query(self):
        return self.server.query(
            retries=1, timeout=QUERY_TIMEOUT_S)

class StatusQuery(AbstractQuery):
    def raw_query(self):
        return self.server.status(
            retries=1, timeout=QUERY_TIMEOUT_S)

def fprint(*args, **kwds):
    print(*args, **kwds)
    kwds.get('file', sys.stdout).flush()

if __name__ == '__main__':
    main()

