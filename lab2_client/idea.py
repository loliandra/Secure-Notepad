import random


# 7.	IDEA, режим сцепления блоков (СВС — Cipher Block Chaining)

def generate_key():
    return random.getrandbits(128)


def get_encode_keys_table(key):
    str_key_inp = bin(key)[2:].zfill(128)
    str_key = ''
    for _ in range(7):
        str_key += str_key_inp
        str_key_inp = str_key_inp[25:] + str_key_inp[:25]
    table = []
    for i in range(8):
        table.append([int(str_key[i * 96:][16 * x: 16 * (x + 1)], 2) for x in range(6)])
    table.append([int(str_key[-128:][16 * x: 16 * (x + 1)], 2) for x in range(4)])

    return table  # строка -- номер раунда


def get_decode_keys_table(key):
    enc_t = get_encode_keys_table(key)

    def si(a):  # add inversion
        a = a % (2 ** 16)
        return 2 ** 16 - a

    def mi(a):  # multiplication inversion
        c = 1
        while True:
            if (c * (2 ** 16 + 1) + 1) % a == 0:
                return int((c * (2 ** 16 + 1) + 1) / a)
            c += 1

    t = []
    r = enc_t[8][:4] + enc_t[7][4:]
    t.append([mi(r[0]), si(r[1]), si(r[2]), mi(r[3]), r[4], r[5]])

    for i in range(1, 8):
        r = enc_t[8 - i][:4] + enc_t[8 - i - 1][4:]
        t.append([mi(r[0]), si(r[2]), si(r[1]), mi(r[3]), r[4], r[5]])
    r = enc_t[0][:4]
    t.append([mi(r[0]), si(r[1]), si(r[2]), mi(r[3])])
    return t


def cipher(message, keys_table):
    def xor(a, b):
        return (a ^ b) % (2 ** 16)

    def sum(a, b):
        return (a + b) % (2 ** 16)

    def mul(a, b):
        a = 2 ** 16 if a == 0 else a
        b = 2 ** 16 if b == 0 else b
        if (a * b) % (2 ** 16 + 1) == 0:
            return 2 ** 16
        return (a * b) % (2 ** 16 + 1)

    def one_cycle(D, K):
        # print('\nKeys ')
        # print(' '.join([hex(K[i]) for i in range(6)]))
        # print('Blocks ')
        # print(' '.join([hex(D[i]) for i in range(4)]))

        A = mul(D[0], K[0])
        B = sum(D[1], K[1])
        C = sum(D[2], K[2])
        D_var = mul(D[3], K[3])
        E = xor(A, C)
        F = xor(B, D_var)

        out1 = xor(A, mul(sum(F, mul(E, K[4])), K[5]))
        out2 = xor(C, mul(sum(F, mul(E, K[4])), K[5]))
        out3 = xor(B, sum(mul(sum(F, mul(E, K[4])), K[5]), mul(E, K[4])))
        out4 = xor(D_var, sum(mul(sum(F, mul(E, K[4])), K[5]), mul(E, K[4])))
        return [out1, out2, out3, out4]

    def last_cycle(D, K):
        # print('\nKeys ')
        # print(' '.join([hex(K[i]) for i in range(4)]))
        # print('Blocks ')
        # print(' '.join([hex(D[i]) for i in range(4)]))
        st1 = mul(D[0], K[0])
        st2 = sum(D[2], K[1])
        st3 = sum(D[1], K[2])
        st4 = mul(D[3], K[3])
        return [el % (2 ** 16) for el in [st1, st2, st3, st4]]

    out = []
    for x in range(int(len(message) / 4)):
        mes = message[4 * x:(x + 1) * 4]

        for round_num in range(8):
            mes = one_cycle(mes, keys_table[round_num])
        mes = last_cycle(mes, keys_table[8])
        out += mes
    return out


# def encode(message, key):
#     if len(message) % 4 != 0:
#         message += (4 - len(message) % 4) * chr(0)
#     mes = [ord(l) for l in message]
#     ints = cipher(mes, get_encode_keys_table(key))
#     return 'G'.join([hex(l) for l in ints])
#
#
# def decode(message, key):
#     mes = [int(l, 16) for l in message.split('G')]
#     ints = cipher(mes, get_decode_keys_table(key))
#     return ''.join([chr(l) for l in ints if chr(l) != chr(0)])


def encode_decode(key, data, iv=bytearray(b'\x00' * 16)):
    n = len(data)
    blocksize = 16
    output = list(data)
    keystream = []

    for i in range(n):
        if len(keystream) == 0:  # encrypt a new counter block when the current keystream is fully used
            iv = cipher(iv, get_encode_keys_table(key))
            keystream = list(iv)
        output[i] = chr(ord(output[i]) ^ (keystream.pop(
            0)))  # as long as an encrypted counter value is available, the output is just "input XOR keystream"

    return ''.join(output)