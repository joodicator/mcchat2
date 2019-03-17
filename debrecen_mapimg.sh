#!/bin/bash

exec python3 $(dirname $0)/mcchat2.py \
    debrecen.fto.zone:32222 \
    hafydd@live.com \
    --password-file /home/jc/git/PageBot/state/mcchat-debrecen.pass \
    --plugins mapimg \
    "$@"
