"""
Implementation of FF3 encryption - supports up to 128 bits
"""

import math
from Crypto.Cipher import AES


def round_function(word, o_n, key, tweak):
    """
    Encryption round function (truncated AES)
    :param word: Input of size log(n) bits
    :param i_n: Domain size of input
    :param o_n: Domain size of output
    :param key: Encryption key
    :param tweak: Round Tweak
    :return: Round function output
    """
    key = key.to_bytes(16, byteorder='big')
    cipher = AES.new(key, AES.MODE_ECB)

    n_bits = math.ceil(math.log(word + 1, 2))

    block = int((tweak << n_bits) + word)
    block = block.to_bytes(16, byteorder='big')

    output = cipher.encrypt(block)
    output = int.from_bytes(output, byteorder='big')

    return output & (o_n - 1)


def calc_round(left, right, o_n, key, tweak, round):
    """
    Calculate full round of FF3
    :param left: Left half of input
    :param right: Right half of input
    :param i_n: Domain size of round function input
    :param o_n: Domain size of round function output
    :param key: Encryption key
    :param tweak: Original tweak (t_l or t_r)
    :param round: Round number
    :return: State after the round
    """
    round_tweak = tweak ^ round

    left = (left + round_function(right, o_n, key, round_tweak)) % o_n
    return right, left


def dec_round(left, right, o_n, key, tweak, round):
    """
    Decrypts full round of FF3
    :param left: Left half of input
    :param right: Right half of input
    :param i_n: Domain size of round function input
    :param o_n: Domain size of round function output
    :param key: Encryption key
    :param tweak: Original tweak (t_l or t_r)
    :param round: Round number
    :return: State after the round
    """
    round_tweak = tweak ^ round

    left = (left - round_function(right, o_n, key, round_tweak)) % o_n
    return right, left


def encrypt(plaintext, key, t_l, t_r, n_bits_l, n_bits_r, num_rounds=8, start_round=0):
    """
    :param plaintext: Tuple of (<left half>, <right half>)
    :param key: Encryption key
    :param t_l: Left tweak
    :param t_r: Right tweak
    :param n_bits_l: bit size of the domain of left half
    :param n_bits_l: bit size of the domain of right half
    :param num_rounds: number of rounds to encrypt
    :param start_round: the round to begin encrypting from
    :param distinguisher_flag: True if testing the general distinguisher
    :return: returns left and right of ciphertext
    """
    n_l = 2 ** n_bits_l
    n_r = 2 ** n_bits_r

    left = plaintext[0]
    right = plaintext[1]
    for i in range(num_rounds):
        if i % 2:
            o_n = n_r
            tweak = t_l
        else:
            o_n = n_l
            tweak = t_r

        if i < start_round:
            left, right = right, left
        else:
            left, right = calc_round(left, right, o_n, key, tweak, i)
    if num_rounds % 2 == 1:
        return right, left

    return left, right


def decrypt(ciphertext, key, t_l, t_r, n_bits_l, n_bits_r, num_rounds=8, start_round=0):
    """
    :param ciphertext: Tuple of (<left half>, <right half>)
    :param key: Encryption key
    :param t_l: Left tweak
    :param t_r: Right tweak
    :param n_bits_l: bit size of the domain of left half
    :param n_bits_l: bit size of the domain of right half
    :param num_rounds: number of rounds to encrypt
    :param start_round: the round to begin encrypting from
    :param distinguisher_flag: True if testing the general distinguisher
    :return: returns left and right of ciphertext
    """
    n_l = 2 ** n_bits_l
    n_r = 2 ** n_bits_r

    if num_rounds % 2:
        left = ciphertext[0]
        right = ciphertext[1]
    else:
        left = ciphertext[1]
        right = ciphertext[0]
    for i in range(num_rounds - 1, -1, -1):
        if i % 2:
            o_n = n_r
            tweak = t_l
        else:
            o_n = n_l
            tweak = t_r

        if i < start_round:
            left, right = right, left
        else:
            left, right = dec_round(left, right, o_n, key, tweak, i)

    return right, left

