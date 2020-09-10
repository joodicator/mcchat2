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
import importlib
import traceback
import functools
import itertools
import errno
import stat

from future.utils import raise_
from builtins import input

import minecraft.authentication as authentication
import minecraft.networking.connection as connection
import minecraft.networking.packets as packets
from minecraft.exceptions import YggdrasilError

import mcstatus
import json_chat

DEFAULT_PORT = 25565

AUTH_TOKENS_FILE      = '.mcchat-auth-tokens'
AUTH_TOKENS_MODE      = stat.S_IRUSR | stat.S_IWUSR
AUTH_TOKENS_MODE_WARN = stat.S_IRWXG | stat.S_IRWXO

KEEPALIVE_TIMEOUT_S        = 30
STANDBY_QUERY_INTERVAL_S   = 5
PREVENT_TIMEOUT_INTERVAL_S = 60
RECONNECT_DELAY_S          = 5

QUERY_ATTEMPTS          = 3
QUERY_RETRY_INTERVAL_S  = 5
QUERY_TIMEOUT_S         = 60
QUERY_TIMEOUT_ATTEMPTS  = 10

NO_TRACE_ERRORS = socket.timeout,

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        'addr',  metavar='HOST[:PORT]',
        help='-- The hostname or IP address of the Minecraft server to which '
        'to connect, and an optional port number defaulting to %d. If HOST is '
        'an IPv6 address, it must be enclosed in square brackets.' % DEFAULT_PORT)
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
        help='-- The version name (such as 1.12, 1.12-pre6, or 17w18b) or protocol '
        'number (such as 333) of the Minecraft version to use when connecting to the '
        'server. If unspecified, the server\'s highest supported version is used.')
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

    match = re.match(r'((?P<host>[^\[\]:]+)|\[(?P<addr>[^\[\]]+)\])'
                     r'(:(?P<port>\d+))?$', args.addr)
    if match is None:
        raise ValueError('Invalid server address: %r.' % options.server)
    host = match.group('host') or match.group('addr')
    port = int(match.group('port')) if match.group('port') else None

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
            spec = importlib.machinery.PathFinder.find_spec(plugin, ['plugins'])
            module = importlib.util.module_from_spec(spec)
            sys.modules[plugin] = module
            spec.loader.exec_module(module)
            plugins.append(module)

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

            if self.connection.connection is not None \
            and self.connection.connection.networking_thread is not None:
                self.connection.connection.networking_thread.join(1)

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

            match = re.match(r'\?exit(\s+(?P<msg>.*))?', text)
            if match:
                msg, quiet, code = match.group('msg') or '', False, 0
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

            match = re.match(r'\?eval\s+(?P<expr>.*)', text)
            if match:
                try:
                    result = eval(match.group('expr'))
                    fprint(repr(result), file=sys.stderr)
                except:
                    traceback.print_exc()
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
                if not isinstance(e, NO_TRACE_ERRORS):
                    traceback.print_exc()
                with self.rlock:
                    fprint('Failed to contact server: %s' % e,
                        file = sys.stderr if self.reconnecting else sys.stdout)
                    self.set_players(None)
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
                        file=sys.stderr if self.reconnecting or
                        self.connecting and self.quiet_start else sys.stdout)
                if isinstance(reason, PermanentExit):
                    self.exit_reason = reason
                    self.exit_cond.notify_all()
                    break
                elif not isinstance(reason, StandbyExit):
                    self.set_players(None)
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
                        file=sys.stderr if self.reconnecting or self.connecting
                        and self.quiet_start else sys.stdout)
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
            old_players = self.players
            self.players = new_players

            if new_players is None:
                self.reported_joined_players.clear()
                self.reported_left_players.clear()
                return            

            with self.connection.rlock:
                profile_name = self.connection.profile_name

            if old_players is not None:
                for added_player in new_players - old_players:
                    if (added_player not in self.reported_joined_players
                    and added_player != profile_name):
                        fprint(json_chat.decode_struct({
                            'translate': 'multiplayer.player.joined',
                            'using': [added_player]}))
                    self.reported_joined_players.add(added_player)
                    self.reported_left_players.discard(added_player)
                for removed_player in old_players - new_players:
                    if (removed_player not in self.reported_left_players
                    and removed_player != profile_name):
                        fprint(json_chat.decode_struct({
                            'translate': 'multiplayer.player.left',
                            'using': [removed_player]}))        
                    self.reported_left_players.add(removed_player)
                    self.reported_joined_players.discard(removed_player)

            if self.standby and not (new_players - {profile_name}):
                self.connection.ensure_disconnected(StandbyExit())

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

        if 'translate' in data and data['translate'].startswith('chat.type.'):
            with self.connection.rlock:
                player = json_chat.decode_struct(using[0])
                if player == self.connection.profile_name:
                    omit_message = True

        chat_string = json_chat.decode_string(packet.json_data)
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
                self.connection.disconnect()
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
            if not isinstance(e, NO_TRACE_ERRORS):
                traceback.print_exc()
            return self.disconnect(e)

        with self.rlock:
            if auth is None:
                kwds = {'username': self.uname}
                self.profile_name = self.uname
            else:
                kwds = {'auth_token': auth}
                self.profile_name = auth.profile.name

            def conn_exception(exc, exc_info):
                with self.rlock:
                    if conn is self.connection:
                        if not isinstance(exc, NO_TRACE_ERRORS):
                            traceback.print_exception(*exc_info)
                        self.disconnect(exc)

            allowed_versions = None if self.version is None else {self.version}
            conn = connection.Connection(
                self.host, self.port, allowed_versions=allowed_versions,
                handle_exception=conn_exception, **kwds)
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
            if not isinstance(e, NO_TRACE_ERRORS):
                traceback.print_exc()
            return self.disconnect(e)

        if self.prevent_timeout:
            thread = Thread(
                target = self.run_prevent_timeout,
                name   = 'Connection.run_prevent_timeout')
            thread.daemon = True
            thread.start()

        if self.no_timeout: return
        while conn is self.connection:
            with self.rlock:
                if not self.keep_alive:
                    self.disconnect('Timed out (%ss).' % KEEPALIVE_TIMEOUT_S)
                    return
                self.keep_alive = False
                self.disconnect_cond.wait(KEEPALIVE_TIMEOUT_S)
   
    def run_prevent_timeout(self):
        with self.rlock:
            while True:
                self.disconnect_cond.wait(PREVENT_TIMEOUT_INTERVAL_S)
                if self.disconnected: break
                packet = packets.AnimationPacketServerbound(
                    hand = packets.AnimationPacketServerbound.HAND_MAIN)
                self.connection.write_packet(packet)

    def authenticate(self):
        with self.rlock:
            if self.offline:
                self.auth_token = None
                return None
            tokens = load_auth_tokens()
            if self.auth_token is None:
                token = tokens.get(self.uname.lower())
                if token is not None:
                    self.auth_token = authentication.AuthenticationToken(
                        username=self.uname,
                        access_token=token['accessToken'],
                        client_token=token['clientToken'])
            if self.auth_token is not None:
                try:
                    self.auth_token.refresh()
                except YggdrasilError:
                    self.auth_token = None
            if self.auth_token is None:
                try:
                    self.auth_token = authentication.AuthenticationToken()
                    self.auth_token.authenticate(self.uname, self.pword)
                except YggdrasilError:
                    self.auth_token = None
                    self._authenticate_save(tokens=tokens)
                    raise
            self._authenticate_save(tokens=tokens)
            return self.auth_token

    def _authenticate_save(self, tokens=None):
        luname = self.uname.lower()
        if tokens is None:
            tokens = load_auth_tokens()
        if self.auth_token is not None:
            tokens[luname] = {
                'accessToken': self.auth_token.access_token,
                'clientToken': self.auth_token.client_token}
        elif luname in tokens:
            del tokens[luname]
        if tokens.get(luname) != self.auth_token:
            save_auth_tokens(tokens)

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
        self.start_query()
        with self.rlock:
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

def load_auth_tokens(file_path=AUTH_TOKENS_FILE):
    if os.path.exists(file_path):
        with open(file_path) as file:
            if os.name == 'posix':
                fstat = os.fstat(file.fileno())
                fmode = stat.S_IMODE(fstat.st_mode)
                if fmode & AUTH_TOKENS_MODE_WARN:
                    fprint('Warning: %s is not protected from access by other'
                           ' users (access mode %03o; should be %03o).'
                           % (AUTH_TOKENS_FILE, fmode, AUTH_TOKENS_MODE),
                           file=sys.stderr)
            try:
                return json.load(file)
            except ValueError:
                pass
    return {}

def save_auth_tokens(auth_tokens, file_path=AUTH_TOKENS_FILE):
    exists = os.path.exists(file_path)
    with open(file_path, 'w') as file:
        json.dump(auth_tokens, file, indent=4)
        if not exists and os.name == 'posix':
            os.fchmod(file.fileno(), AUTH_TOKENS_MODE)

if __name__ == '__main__':
    main()
