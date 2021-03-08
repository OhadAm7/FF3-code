"""
Symmetric differential slide attack on FF3 - Section 4.1
"""

import sys
from common import key_init, encryption_oracle, codebook_oracle, make_chains, extend_chain, process, dist, reconstruct
import time
import math
import numpy as np


def symmetric_slide(u_chain, bins, v_chain, n_bits, cycle_len, mu, key, t_l, t_r, query_table, reverse=False):
    """
    Given two chains, slide them against each other until reconstruction is successful
    :param u_chain: Chain of type g(f())
    :param bins: List of lists of plaintexts with common right-hand-side, along with indices
    :param v_chain: Chain of type f(g())
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_len: Length of cycles in the codebook reconstruction attack
    :param mu: Number of times to attempt round function restoration
    :param key, t_l, t_r: Encryption parameters
    :param query_table: Used to track oracle queries
    :param reverse: True if the slide is using the modified tweaks
    :return: 8-round FF3 codebook if succeeded, None if failed
        Also returns separate success rates of distinguisher and codebook reconstruction
    """
    n = 2 ** n_bits

    # For testing
    reconstruction_success = 0
    reconstruction_fail = 0
    combined_rec_success = 0
    combined_rec_fail = 0
    true_pos = 0
    true_neg = 0
    false_pos = 0
    false_neg = 0

    # Try reconstruction for each slide distance
    for i in range(int((len(u_chain) - 1) / 2)):
        # Check that it is a slid pair
        if dist(bins, v_chain, -i, n_bits, delta):
            if encryption_oracle(u_chain[i], v_chain[0], key, t_l, t_r, n_bits, 4):
                true_pos += 1

                # Extend chains if necessary
                if len(u_chain) < 2 * p:
                    u_chain = extend_chain(u_chain, 2 * p, n_bits, key, t_l, t_r, query_table)
                    v_chain = extend_chain(v_chain, 2 * p, n_bits, key, t_l ^ 4, t_r ^ 4, query_table)
                    mid_chain = p
                else:
                    mid_chain = int((len(u_chain) - 1) / 2)

                if np.all(u_chain is None) or np.all(v_chain is None):
                    return None, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail,\
                           true_pos, true_neg, false_pos, false_neg

                f_x_chain = u_chain[mid_chain: mid_chain + p]
                f_y_chain = v_chain[mid_chain - i: mid_chain + p - i]
                g_x_chain = v_chain[0: p]
                g_y_chain = u_chain[i + 1: i + p + 1]

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
                    if reverse:
                        for plaintext in range(n ** 2):
                            codebook.append(f[g[plaintext]])
                    else:
                        for plaintext in range(n ** 2):
                            codebook.append(g[f[plaintext]])
                    return codebook, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail,\
                           true_pos, true_neg, false_pos, false_neg
            else:
                false_pos += 1

        elif encryption_oracle(u_chain[i], v_chain[0], key, t_l, t_r, n_bits, 4):
            false_neg += 1
        else:
            true_neg += 1
    return None, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos, false_neg


def slide_attack(n_bits, cycle_len, mu, batch_id, test_id, t=0.0):
    """
    Run the slide attack on random parameters
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_len: Length of cycles in cycle_finder attack
    :param mu: Number of times to attempt round function restoration
    :param batch_id: ID of current test batch
    :param test_id ID of current test
    :param t: parameter for the time-data tradeoff
    :return: 8-round FF3 codebook if succeeded, None if failed
        Also returns separate success rates of codebook reconstruction and distinguisher
    """
    # For testing
    query_table = {}

    key, t_l, t_r = key_init(n_bits, batch_id, test_id)

    u_chains = make_chains(num_chains, half_chain_len, p, n_bits, key, t_l, t_r, batch_id, test_id, query_table)

    v_chains = make_chains(num_chains, half_chain_len, p, n_bits, key, t_l ^ 4, t_r ^ 4, batch_id, test_id, query_table)

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

    for u_chain in u_chains:
        # Preprocess the second half of u_chain
        bins = process([(u_chain[i], i) for i in range(half_chain_len + 1, 2 * half_chain_len + 1)], n_bits, t)

        for v_chain in v_chains:
            c, successes, failures, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos,\
                false_neg = symmetric_slide(u_chain, bins, v_chain, n_bits, cycle_len, mu, key, t_l, t_r, query_table)
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
                return success, reconstruction_success, reconstruction_fail, sum_combined_rec_success, sum_combined_rec_fail,\
                       sum_true_pos, sum_true_neg, sum_false_pos, sum_false_neg, len(query_table.keys())
                return c    # This is the full codebook reconstructed by the attack

    # Slide from the other direction
    for v_chain in v_chains:
        # Preprocess the second half of u_chain
        bins = process([(v_chain[i], i) for i in range(half_chain_len + 1, 2 * half_chain_len + 1)], n_bits, t)

        for u_chain in u_chains:
            c, successes, failures, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos,\
                false_neg = symmetric_slide(v_chain, bins, u_chain, n_bits, cycle_len, mu, key, t_l ^ 4, t_r ^ 4, query_table, True)
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
                return success, reconstruction_success, reconstruction_fail, sum_combined_rec_success, sum_combined_rec_fail,\
                       sum_true_pos, sum_true_neg, sum_false_pos, sum_false_neg, len(query_table.keys())
                return c    # This is the full codebook reconstructed by the attack
    return None, reconstruction_success, reconstruction_fail, sum_combined_rec_success, sum_combined_rec_fail, sum_true_pos, sum_true_neg, sum_false_pos, sum_false_neg, len(query_table.keys())


if __name__ == "__main__":
    n_bits = int(sys.argv[1])
    cycle_len = int(sys.argv[2])
    mu = int(sys.argv[3])
    t = float(sys.argv[4])
    t_flag = int(sys.argv[5])   # 0 if t represents the parameter t, 1 if it represents the number of bins
    batch_id = int(sys.argv[6])
    test_id = int(sys.argv[7])

    n = 2 ** n_bits

    start = time.time()

    if t_flag:
        t = math.log(t, 2) / (4 * n_bits)

    # Global parameters
    delta = 1.6 / n     # Threshold for the distinguisher
    eps = 1 / (2 * cycle_len)
    q = int(n * (10 * n * n_bits) ** 0.5)  # The length needed for the distinguisher

    num_chains = int(
        (0.75 ** 0.5 / 10 ** 0.25) * (n ** (0.25 + t)) * n_bits ** (-0.25))  # So we get O(N^2) slide attempts overall

    half_chain_len = int(q * (n ** (-2 * t)))

    p = int((2 ** (1. / 3)) * (n ** (1.5 + eps)))  # The length needed for codebook reconstruction

    success, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos,\
        false_neg, num_queries = slide_attack(n_bits, cycle_len, mu, batch_id, test_id, t)

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
