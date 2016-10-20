# mcchat2
A machine-usable Minecraft chat console client.

## Contents
1. [Dependencies](#dependencies)
2. [Installation and Usage](#installation-and-usage)
3. [Special Input Sequences](#special-input-sequences)
  1. [`?query`](#query-name)
  2. [`?exit`](#exit)
  3. [`--auto-query`](#--auto-query)
4. [Available Plugins](#available-plugins)
  1. [`mapimg`](#mapimg)

## Dependencies

### Required
* [Python](http://python.org/) 2.7 or 3
* [future](http://python-future.org)
* [mcstatus](//github.com/joodicator/mcstatus) (included as a Git submodule)
  * [dnspython](http://www.dnspython.org)
  * [six](https://pythonhosted.org/six)
* [pyCraft](//github.com/ammaraskar/pyCraft) (included as a Git submodule)
  * [cryptography](https://cryptography.io)
  * [requests](http://python-requests.org)

### Optional
* [mcmapimg](//github.com/joodicator/mcmapimg) (for the `mapimg` plugin; included as a Git submodule)
  * [PIL](http://www.pythonware.com/products/pil)
  * [PyNBT](https://github.com/TkTech/PyNBT) (included as a Git submodule)
* [Git](http://git-scm.com) (to install from GitHub)

## Installation and Usage

1.  Clone this repository into an empty directory:
    ```
    git clone https://github.com/joodicator/mcchat2
    cd mcchat2
    ```

2.  Initialise the submodules:
    ```
    git submodule update --init --recursive
    ```

3.  For information on the command-line arguments of mcchat2, see:
    ```
    ./mcchat2.py --help
    ```

## Special Input Sequences

While running, each line from mcchat2's standard input is sent to the server (if connected) as one or more chat messages, unless it takes one of the following special forms:

#### `?query NAME`

Ask for the value of the property called `NAME`. The program responds by printing to standard output (possibly after a delay during which other unrelated messages may be printed) either
  
  * `!query success NAME VALUE...`  or
  * `!query failure NAME REASON...`

If the same property is queried more than once, the program *may* respond by issuing only a single reply for several identical queries. The property `NAME` may be any of the following:
  
  * `players` - the names of all players on the server, separated by spaces. Only available when connected.
  * `agent` - the player name that mcchat2 appears as on the server. Only available when connected.
  * Any key from [the key/value section of Minecraft's query interface](http://wiki.vg/Query#K.2C_V_section). Only available when the server's UDP query interface is enabled.

#### `?exit [--quiet] [REASON...]`

Cause the program to disconnect from the server if connected, and then terminate, printing the given exit reason to standard error if currently disconnected from the server in standby mode and the `--quiet` flag is included, or otherwise to standard output. If `REASON` is not given, it defaults to `Manually closed.` The `--quiet` flag is useful in combination with the `--quiet-start` command-line flag of mcchat2 to restart the client when it is in standby mode, without causing unnecessary noise.

#### `--auto-query`

If this command-line option is present, then, when starting and whenever successfully connecting to the server after having previously been disconnected, mcchat2 automatically acts as if `?query map` were issued; and, when successfully connecting to the server, mcchat2 acts as if `?query agent` were issued. This allows a program listening to mcchat2's standard output to stay up to date with the values of these properties without knowing the internal state of mcchat2.

## Available Plugins

#### `mapimg`
When mcchat2 is run with this plugin loaded, e.g. with `--plugins mapimg` in its command-line arguments, then any maps encountered by the client are saved as two image files in `plugins/mapimg/maps`:

1. `map_NUMBER.png` - the main map image without any icons.
2. `map_NUMBER_icons.png` - an otherwise transparent image containing any map icons.
