from __future__ import print_function

import os.path
import sys

from .mcmapimg import mcmapimg
from minecraft.networking.packets import MapPacket

map_set = None

def install(conn):
    global map_set
    map_set = MapPacket.MapSet()
    conn.register_packet_listener(h_map, MapPacket)

def h_map(packet):
    global map_set
    packet.apply_to_map_set(map_set)
    map = map_set.maps_by_id[packet.map_id]

    if packet.pixels is not None:
        file_path = os.path.join(
            os.path.dirname(__file__), 'maps', 'map_%d.png' % map.id)
        with open(file_path, 'wb') as file:
            mcmapimg.map_data_to_img(map.pixels, file,
                width=map.width, height=map.height, warn=True)
        print('mapimg: updated %s.' % file_path, file=sys.stderr)

    file_path = os.path.join(
        os.path.dirname(__file__), 'maps', 'map_%d_icons.png' % map.id)
    icons = [(i.type, i.direction, i.location) for i in map.icons]
    with open(file_path, 'wb') as file:
        mcmapimg.map_icons_to_img(icons, file,
            width=map.width, height=map.height, scale=1)
