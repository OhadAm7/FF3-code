"""
Asymmetric differential slide attack on FF3 - Section 4.3
"""

import sys
from common import key_init, encryption_oracle, codebook_oracle, make_chains, extend_chain, reconstruct
from collections import defaultdict
import time
import math
import numpy as np


def asymmetric_slide(u_chains, processed_u, v_chain, n_bits, cycle_len, mu, key, t_l, t_r, query_table):
    """
    Given two chains, slide them against each other until reconstruction is successful
    :param u_chain: Chain of type g(f())
    :param processed_u: u_chain processed according to right-hand-side, along with original indices
    :param v_chain: Chain of type f(g())
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_len: Length of cycles in the codebook reconstruction attack
    :param mu: Number of times to attempt round function restoration
    :param key, t_l, t_r: Encryption parameters
    :param query_table: Used to track oracle queries
    :return: 8-round FF3 codebook if succeeded, None if failed
        Also returns separate success rates of distinguisher and codebook reconstruction
    """
    n = 2 ** n_bits

    num_chains_p = len(u_chains)

    threshold = delta * q * (q - 1) / (2 * n ** 2)

    kilist = np.zeros((num_chains_p, q + 1), dtype=np.uint32)

    # For testing
    reconstruction_success = 0
    reconstruction_fail = 0
    combined_rec_success = 0
    combined_rec_fail = 0
    true_pos = 0
    true_neg = 0
    false_pos = 0
    false_neg = 0

    for i in range(q + 1):
        for j in range(i + 1, q + 1):
            leftdiff = (v_chain[j][0] - v_chain[i][0]) % n
            for plain_index in processed_u[(j - i, leftdiff)]:
                k = plain_index[0]
                plain_i = plain_index[1]
                if 0 <= plain_i - i <= q:
                    kilist[k][plain_i - i] += 1

    max_index = np.argsort(kilist, axis=None)[::-1][0]
    k, offset = np.unravel_index(max_index, kilist.shape)

    maxvalue = kilist[k][offset]
    if maxvalue >= threshold:
        if encryption_oracle(u_chains[k][q], v_chain[q - offset], key, t_l, t_r, n_bits, 4):
            true_pos += 1

            f_x_chain = extend_chain(u_chains[k][q: q + 1], new_len, n_bits, key, t_l, t_r, query_table)
            f_y_chain = extend_chain(v_chain[q - offset: q - offset + 1], new_len, n_bits, key, t_l ^ 4, t_r ^ 4, query_table)

            if np.all(f_x_chain is None) or np.all(f_y_chain is None):
                return None, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos, false_neg

            g_x_chain = extend_chain(v_chain[0: 1], new_len, n_bits, key, t_l ^ 4, t_r ^ 4, query_table)
            g_y_chain = extend_chain(u_chains[k][offset + 1: offset + 2], new_len, n_bits, key, t_l, t_r, query_table)

            if np.all(g_x_chain is None) or np.all(g_y_chain is None):
                return None, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos, false_neg

            f = reconstruct(f_x_chain, f_y_chain, n_bits, cycle_len, mu)
            g = reconstruct(g_x_chain, g_y_chain, n_bits, cycle_len, mu)

            # For testing
            f_success = codebook_oracle(f, key, t_l, t_r, n_bits, 4)
            g_success = codebook_oracle(g, key, t_l ^ 4, t_r ^ 4, n_bits, 4)

            reconstruction_success += (int(f_success) + int(g_success))
            reconstruction_fail += (int(not f_success) + int(not g_success))
            combined_rec_success += (int(f_success and g_success))
            combined_rec_fail += (int(not (f_success and g_success)))

            if f is not None and g is not None:
                codebook = []
                for plaintext in range(n ** 2):
                    codebook.append(g[f[plaintext]])
                return codebook, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, \
                       true_pos, true_neg, false_pos, false_neg
        else:
            false_pos += 1

    elif encryption_oracle(u_chains[k][0], v_chain[offset], key, t_l, t_r, n_bits, 4):
        false_neg += 1
    else:
        true_neg += 1
    return None, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos, false_neg


def process_plaintext(u_chains, q, n_bits):
    """
    Process u_chains according to right hand side
    :param u_chains: Chains of plaintexts
    :param q: Amount of plaintexts needed for distinguisher
    :param n_bits: Half the bit size of the encryption domain
    :return: Table of processed plaintexts
    """
    n = 2 ** n_bits

    table = defaultdict(list)

    for k in range(len(u_chains)):
        s = defaultdict(list)

        for i in range(2 * q + 1):
            s[u_chains[k][i][1]].append(i)

        for partition in s.keys():
            for i in range(len(s[partition])):
                small_i = s[partition][i]
                for j in range(i + 1, len(s[partition])):
                    big_i = s[partition][j]
                    if big_i - small_i < q:
                        leftdiff = (u_chains[k][big_i][0] - u_chains[k][small_i][0]) % n
                        table[(big_i - small_i, leftdiff)].extend([(k, small_i)])

    return table


def slide_attack(n_bits, cycle_len, mu, batch_id, test_id):
    """
    Run the slide attack on random parameters
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_len: Length of cycles in cycle_finder attack
    :param mu: Number of times to attempt round function restoration
    :param batch_id: ID of current test batch
    :param test_id ID of current test
    :return: 8-round FF3 codebook if succeeded, None if failed
        Also returns separate success rates of codebook reconstruction and distinguisher
    """
    # For testing
    query_table = {}

    key, t_l, t_r = key_init(n_bits, batch_id, test_id)

    u_chains = make_chains(num_chains_p, q, new_len, n_bits, key, t_l, t_r, batch_id, test_id, query_table)

    v_chains = make_chains(num_chains_c, q, new_len, n_bits, key, t_l ^ 4, t_r ^ 4, batch_id, test_id, query_table)

    if u_chains is None or v_chains is None:
        return None, 0, 0, 0, 0, 0, 0, 0, 0, len(query_table.keys())

    # For testing - sum up the data from all chain pairs
    reconstruction_success = 0
    reconstruction_fail = 0
    sum_combined_rec_success = 0
    sum_combined_rec_fail = 0
    sum_true_pos = 0
    sum_true_neg = 0
    sum_false_pos = 0
    sum_false_neg = 0

    table_u = process_plaintext(u_chains, q, n_bits)

    for v_chain in v_chains:
        c, successes, failures, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos, false_neg \
            = asymmetric_slide(u_chains, table_u, v_chain, n_bits, cycle_len, mu, key, t_l, t_r, query_table)
        reconstruction_success += successes
        reconstruction_fail += failures
        sum_combined_rec_success += combined_rec_success
        sum_combined_rec_fail += combined_rec_fail
        sum_true_pos += true_pos
        sum_true_neg += true_neg
        sum_false_pos += false_pos
        sum_false_neg += false_neg
        if c is not None:
            success = codebook_oracle(c, key, t_l, t_r, n_bits, 8)
            return success, reconstruction_success, reconstruction_fail, sum_combined_rec_success, sum_combined_rec_fail, \
                   sum_true_pos, sum_true_neg, sum_false_pos, sum_false_neg, len(query_table.keys())
            return c    # This is the full codebook reconstructed by the attack
    return None, reconstruction_success, reconstruction_fail, sum_combined_rec_success, sum_combined_rec_fail, sum_true_pos,\
           sum_true_neg, sum_false_pos, sum_false_neg, len(query_table.keys())


if __name__ == "__main__":
    n_bits = int(sys.argv[1])
    cycle_len = int(sys.argv[2])
    mu = int(sys.argv[3])
    t = float(sys.argv[4])
    t_flag = int(sys.argv[5])   # 0 if t represents the parameter t, 1 if it represents the number of chains
    batch_id = int(sys.argv[6])
    test_id = int(sys.argv[7])

    n = 2 ** n_bits

    start = time.time()

    # Global parameters
    delta = 1.6     # Threshold for the distinguisher
    eps = 1 / (2 * cycle_len)
    q = int(((10 * n_bits) ** (1. / 2)) * n)     # The length needed for the distinguisher

    if t_flag:
        num_chains_c = int(t)
    else:
        num_chains_c = math.ceil(n ** t * (1.5 / (10 * n_bits) ** 0.5) ** 0.5)

    num_chains_p = math.ceil(1.5 * n / (num_chains_c * (10 * n_bits) ** 0.5))

    new_len = int((2 ** (1. / 3)) * (n ** (1.5 + eps)))     # The length needed for codebook reconstruction

    success, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos,\
        false_neg, num_queries = slide_attack(n_bits, cycle_len, mu, batch_id, test_id)

    end = time.time()

    if success:
        print(1)
    else:
        print(0)
    print(reconstruction_success)
    print(reconstruction_fail)
    print(combined_rec_success)
    print(combined_rec_fail)
    print(true_pos)
    print(true_neg)
    print(false_pos)
    print(false_neg)
    print(num_queries)
    print(end - start)