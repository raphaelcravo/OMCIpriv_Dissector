import binascii
import re
import sys

filename = sys.argv[1]
omci_pattern = re.compile(r'\w{32}0{11}[1-2]\w{12}88b5\w{96}')

with open(filename, 'rb') as f:
    hexrawdata = str(binascii.hexlify(f.read()))


def reversehex(value):
    value_ls = [value[i:i + 2] for i in range(0, len(value), 2)]
    value_ls.reverse()
    return ''.join(value_ls)


for omcipkt in re.findall(omci_pattern, hexrawdata):
    rawomcisamplefile = filename + '_raw_sample'
    with open(rawomcisamplefile, 'a') as output_file:
        output_file.write(omcipkt + '\n\n')
