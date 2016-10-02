# mcchat2
A machine-usable Minecraft chat console client.

## Contents
1. [Dependencies](#dependencies)
2. [Installation and Usage](#installation-and-usage)
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

## Available Plugins

#### `mapimg`
When mcchat2 is run with this plugin loaded, e.g. with `--plugins mapimg` in its command-line arguments, then any maps encountered by the client are saved as two image files in `plugins/mapimg/maps`:

1. `map_NUMBER.png` - the main map image without any icons.
2. `map_NUMBER_icons.png` - an otherwise transparent image containing any map icons.
