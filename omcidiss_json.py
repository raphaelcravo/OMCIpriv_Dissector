import binascii
import re
from tabulate import tabulate
import sys
import json
import pandas as pd

filename = sys.argv[1]
omci_pattern = re.compile(r'\w{32}0{11}[1-2]\w{12}88b5\w{96}')
index_interval = 3
tblfmt = 'psql'

typecodes = {
    '4': '(4) CREATE',
    '6': '(6) DELETE',
    '8': '(8) SET',
    '9': '(9) GET',
    '16': '(16) ALARM',
    '2': 'not implemented, TO DO',
    'b': 'not implemented, TO DO',
}
msg_direction = {
    '1': 'ONU -> OLT',
    '2': 'OLT -> ONU'
}
respcodes = {
    '00': '(00) Command processed successfully',
    '01': '(01) Command processed ERROR',
    '02': '(02) Command NOT SUPPORTED',
    '03': '(03) Parameter ERROR',
    '04': '(04) UNKNOW managed entity',
    '05': '(05) UNKNOW managed entity instance',
    '06': '(06) Device BUSY',
    '07': '(07) Instance Exists'
}
ack_codes = {
    "0": "(00) - no ACK",
    "2": "(02) - ACK response",
    "4": "(04) - ACK request",
    "5": 'not implemented, TO DO',
    '1': 'not implemented, TO DO',
    '3': 'not implemented, TO DO',
}

start_timestamp = 0
config_index = 0
packet_index = 0
pktdata = {}

with open(filename, 'rb') as f:
    hexrawdata = str(binascii.hexlify(f.read()))


def reversehex(value):
    value_ls = [value[i:i + 2] for i in range(0, len(value), 2)]
    value_ls.reverse()
    return ''.join(value_ls)


def attmaskdissector(value):
    value = bin(int(value, 16))[2:].zfill(16)
    value_ls = [str(i + 1) for i, char in enumerate(value) if char == "1"]
    return ','.join(value_ls)


def attdata_to_dec(value, byteslen):
    value_ls = [str(int(value[i:i + byteslen * 2], 16)) for i in range(0, len(value), byteslen * 2)]
    return ''.join(value_ls)


def attdata_to_ascii(value):
    value_ls = [str(bytes.fromhex(value[i:i + 2]))[-2] for i in range(0, len(value), 2)]
    return ''.join(value_ls)


for omcipkt in re.findall(omci_pattern, hexrawdata):
    packet_index += 1
    timestamp = int(reversehex(omcipkt[0:8]), 16)

    if timestamp - start_timestamp > index_interval:
        config_index += 1
        start_timestamp = timestamp
        pktdata['config' + str(config_index)] = {}

    pktdata['config' + str(config_index)].update(
        {

            str(packet_index):
                {
                    'direction': msg_direction[omcipkt[43]],
                    'transaction_id': int(omcipkt[60:64], 16),
                    'ackflag': ack_codes[omcipkt[64]],
                    'msgtype': typecodes[omcipkt[65]],
                    'meclass': int(omcipkt[68:72], 16),
                    'meinstance': int(omcipkt[72:76], 16),
                }
        }
    )

    if omcipkt[65] == '8' and omcipkt[64] != '2':
        descr = 'OLT is trying to config ME {} at instance {}, with '
        pktdata['config' + str(config_index)][str(packet_index)].update(
            {
                'att_bitmask': omcipkt[76:80],
                'att_maskresult': attmaskdissector(omcipkt[76:80]),
                'att_rawdata': omcipkt[80:140],
                'att_dec1byte': attdata_to_dec(omcipkt[80:140], 1),
                'att_dec2byte': attdata_to_dec(omcipkt[80:140], 2),
                'att_ascii': attdata_to_ascii(omcipkt[80:140])

            }
        )



with open('result.json', 'w') as fp:
    json.dump(pktdata, fp)


