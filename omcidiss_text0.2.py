import binascii
import re
from tabulate import tabulate
import sys

filename = sys.argv[1]
omci_pattern = re.compile(r'\w{32}0{11}[1-2]\w{12}88b5\w{96}')  # Expressão regular que representa o padrão que indica
# um cabeçalho de frame OMCI.

typecodes = {'44': 'Create ME inst', '24': 'Ack Create', '48': 'Set ME instance'}
mactodirection = {'1': 'ONU -> OLT', '2': 'OLT -> ONU'}
tblfmt = 'psql'
index_interval = 3

# sampleomci =
# '5c0fef5d12da07003e0000003e00000000000000000200194651286f88b5d812440aff640000070000000000000000000000000000000000000000000000000000000000000000000028cfdf13a9'

start_timestamp = 0  # Referencia para calcular o tempo entre os frames OMCI. o primeiro frame OMCI detectado
# é colocado no tempo 0 segundo.
config_index = 0  # Indicador de grupo de frames que pertencem a mesma configuração. Frames dentro da janela de tempo
# definida em index_interval são classificadas como pertencentes ao mesmo grupo, e consequentemente,
# a mesma configuração.
packet_index = 0  # Indice de sequencia do frame OMCI
result = {}  # Dados brutos do frame OMCI

# Extrai os dados brutos, em hexadecimal, de um arquivo .pcap e o converte para string
with open(filename, 'rb') as f:
    hexrawdata = str(binascii.hexlify(f.read()))


def reversehex(value):
    # Por alguma razão que ainda desconheço, o hexlify inverte alguns valores hex. por exemplo, o que deveria ser f8
    # d1 aparece como d1 f8. Enquanto eu não descubro o pq, estou usando esta função.
    value_ls = [value[i:i + 2] for i in range(0, len(value), 2)]
    value_ls.reverse()
    return ''.join(value_ls)


def attmaskdissector(value):
    # Retorna uma string com os índices de atributos, separados por vírgula, através do valor hexadecimal
    # da máscara de atributos.
    value = bin(int(value, 16))[2:].zfill(16)  # Converte valor de hex para máscara bionária
    value_ls = [str(i + 1) for i, char in enumerate(value) if char == "1"]  # Cria uma lista com os índices dos bits
    # que estão ligados
    return ','.join(value_ls)  # Retorna uma string com os índices de atributos


def attdata_to_dec(value, byteslen):
    # Converte uma string representando caracteres hexadecimais em uma sequencia de numeros decimais, a depender de
    # quantos bytes cada valor decimal vai ter. Exemplos: (c0a80a01, 1) retorna a string 192168101 (útil para achar
    # valores de 1 byte, como octetos de endereços IPv4 ou outros valores de 1 byte. (07d0, 4) irá retornar 2000,
    # útil para encontrar valores de vlans.
    value_ls = [str(int(value[i:i + byteslen * 2], 16)) for i in range(0, len(value), byteslen * 2)]
    return ''.join(value_ls)


def attdata_to_ascii(value):
    # Converte uma string representando caracteres hexadecimais em caracteres ASCII
    value_ls = [str(bytes.fromhex(value[i:i + 2]))[-2] for i in range(0, len(value), 2)]
    return value_ls


for omcipkt in re.findall(omci_pattern, hexrawdata):
    packet_index += 1
    timestamp = int(reversehex(omcipkt[0:8]), 16)
    dstmac = omcipkt[43]
    transaction_id = omcipkt[60:64]
    msgtype = omcipkt[64:66]
    meclass = omcipkt[68:72]
    meinstance = omcipkt[72:76]

    if timestamp - start_timestamp > index_interval:
        config_index += 1
        start_timestamp = timestamp
        result['config' + str(config_index)] = {}

    if msgtype == '44':
        strtype = 'OLT requires creation of ME ' + str(int(meclass, 16)) + ' instance ' + str(
            int(meinstance, 16)) + ' on ONU with transaction ID: ' + str(int(transaction_id, 16))
        result['config' + str(config_index)].update(
            {

                str(packet_index):
                    {
                        'msgtype': msgtype,
                        'dstmac': dstmac,
                        'transaction_id': transaction_id,
                        'meclass': meclass,
                        'meinstance': meinstance,
                        'strtype': strtype
                    }
            }
        )
    elif msgtype == '24':
        code_result = omcipkt[76:78]
        if code_result != '00':
            strtype = 'ONU says that the command with transaction ID: ' + str(
                int(transaction_id, 16)) + ' was successfully processed'
        else:
            strtype = 'ONU did not accept the command with transaction ID: ' + str(int(transaction_id, 16))

        result['config' + str(config_index)].update(
            {
                str(packet_index):
                    {
                        'msgtype': msgtype,
                        'dstmac': dstmac,
                        'transaction_id': transaction_id,
                        'meclass': meclass,
                        'meinstance': meinstance,
                        'strtype': strtype,
                    }
            }
        )

    elif msgtype == '48':
        att_mask = omcipkt[76:80]
        att_indexes = attmaskdissector(att_mask)
        att_hexdata = omcipkt[80:140]
        att_asciidata = attdata_to_ascii(att_hexdata)
        att_decdata1byte = attdata_to_dec(att_hexdata, 1)
        att_decdata2bytes = attdata_to_dec(att_hexdata, 2)

        strtype = 'OLT is trying to set config params on ONU ME ' + str(int(meclass, 16)) + ' instance ' + str(
            int(meinstance, 16)) + ' with transaction ID: ' + str(int(transaction_id, 16))
        result['config' + str(config_index)].update(
            {
                str(packet_index):
                    {
                        'msgtype': msgtype,
                        'dstmac': dstmac,
                        'transaction_id': transaction_id,
                        'meclass': meclass,
                        'meinstance': meinstance,
                        'att_mask': att_mask,
                        'att_indexes': att_indexes,
                        'hex_data': att_hexdata,
                        'hex1bytedec_data': att_decdata1byte,
                        'hex2bytedec_data': att_decdata2bytes,
                        'ascii_data': att_asciidata,
                        'strtype': strtype,

                    }
            }
        )

    else:
        strtype = 'OMCI dissector to be developed, probably no-private OMCI'
        att_hexdata = omcipkt[80:140]
        att_asciidata = attdata_to_ascii(att_hexdata)
        att_decdata1byte = attdata_to_dec(att_hexdata, 1)
        att_decdata2bytes = attdata_to_dec(att_hexdata, 2)
        att_decdata4bytes = attdata_to_dec(att_hexdata, 4)
        result['config' + str(config_index)].update(
            {
                packet_index:
                    {
                        'msgtype': msgtype,
                        'dstmac': dstmac,
                        'transaction_id': transaction_id,
                        'meclass': meclass,
                        'meinstance': meinstance,
                        'hex_data': att_hexdata,
                        'hex1bytedec_data': att_decdata1byte,
                        'hex2bytedec_data': att_decdata2bytes,
                        'hex4bytedec_data': att_decdata4bytes,
                        'ascii_data': att_asciidata,
                        'strtype': strtype,

                    }
            }
        )


def omcidata_render(data, index):
    index = str(index)
    if data['msgtype'] in ['44', '24']:
        headerdata = [['Hex Value', data['msgtype'], data['meclass'], data['meinstance']], [
            'Literal value', typecodes[data['msgtype']], int(data['meclass'], 16), int(data['meinstance'], 16)]]
        headerdata = tabulate(headerdata, headers=[mactodirection[data['dstmac']], 'Type', 'ME ID', 'ME Instance'],
                              tablefmt=tblfmt)
        descr = data['strtype']
        return str('==>OMCI PACKET ' + index + '\n' + headerdata + '\n' + descr + '\n\n\n')

    elif data['msgtype'] == '48':
        headerdata = [['Hex Value', data['msgtype'], data['meclass'], data['meinstance'], data['att_mask']], [
            'Literal value', typecodes[data['msgtype']], int(data['meclass'], 16), int(data['meinstance'], 16),
            data['att_indexes']]]
        headerdata = tabulate(headerdata, headers=[mactodirection[data['dstmac']], 'Type', 'ME ID', 'ME Instance',
                                                   'ME attributes indexes'],
                              tablefmt=tblfmt)
        descr = data['strtype']
        hex1bytedec_data = ''.join(data['hex1bytedec_data'])
        hex2bytedec_data = ''.join(data['hex2bytedec_data'])
        ascii_data = ''.join(data['ascii_data'])
        hex_data = data['hex_data']

        return str('==>OMCI PACKET ' + index + '\n' +
                   headerdata + '\n' + descr + '\n' + 'Attribute data in decimal 1byte mode:' + '\n' + hex1bytedec_data + '\n' +
                   'Attribute data in decimal 2byte mode:' + '\n' + hex2bytedec_data + '\n' + 'Attribute data in '
                                                                                              'ASCII mode:' + '\n' +
                   ascii_data + '\n' + 'attribute data in raw hex mode' + '\n' + hex_data + '\n\n\n')
    else:
        return str('==>OMCI PACKET ' + index + '\n' + 'dissector para este tipo em desenvolvimento \n\n\n')


for cfggroup in result:
    configfile = filename + cfggroup
    with open(configfile, 'a') as output_file:
        for pktindex in result[cfggroup]:
            entry = omcidata_render(result[cfggroup][pktindex], pktindex)
            output_file.write(entry)
