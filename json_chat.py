from __future__ import print_function

from itertools import *
import os.path
import json
import sys
import re

class DecodeError(Exception):
    pass

def load_language(file):
    language = dict()
    for line in file:
        try: name, value = line.split('=', 1)
        except ValueError: continue
        language[name] = value.strip()
    return language

with open(os.path.join(os.path.dirname(__file__), './en_US.lang')) as file:
    language = load_language(file)

def decode_string(data):
    try:
        return decode_struct(json.loads(data))
    except DecodeError as e:
        print(e, file=sys.stderr)
        return data

def decode_struct(data):
    if type(data) is str or type(data) is unicode:
        return data
    elif type(data) is list:
        return ''.join(decode_struct(part) for part in data)
    elif type(data) is dict:
        if 'text' in data:
            result = decode_struct(data['text'])
        elif 'translate' in data:
            using = data.get('using') or data.get('with') or []
            using = [decode_struct(item) for item in using]
            result = translate(data['translate'], using)
        else:
            raise DecodeError
        if 'extra' in data:
            result += decode_struct(data['extra'])
        return result
    else:
        raise DecodeError

def translate(id, params):
    if id not in language: raise DecodeError

    ord_params = params[:]
    def repl(match):
        if match.group() == '%%':
            return '%'
        elif match.group('index'):
            index = int(match.group('index')) - 1
            if index >= len(params): raise DecodeError(
                'Index %s in "%s" out of bounds for %s.'
                % (match.group(), language[id], params))
            param = params[index]
        elif match.group('rest') != '%':
            if not ord_params: raise DecodeError(
                'Too few arguments for "%s" in %s.'
                % (language[id], params))
            param = ord_params.pop(0)
        return ('%' + match.group('rest')) % param

    return re.sub(
        r'%((?P<index>\d+)\$)?(?P<rest>(\.\d+)?[a-zA-Z%])',
        repl, language[id])
