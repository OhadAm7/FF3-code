"""
Cycle structure slide attack on FF3 - Section 4.2
"""

import sys
import ff3
from common import key_init, encryption_oracle, codebook_oracle, process, dist, reconstruct
from collections import defaultdict
import hashlib
import time
import math
import numpy as np


def make_cycle_chains(n_bits, key, t_l, t_r, batch_id, test_id, query_table):
    """
    Find two matching cyclic chains of size about N^(1.5+eps)
    :param n_bits: Half the bit size of the encryption domain
    :param key: Encryption key
    :param t_l: Left tweak
    :param t_r: Right tweak
    :param batch_id: ID of current test batch
    :param test_id: ID of current test
    :param query_table: Used to track oracle queries
    :return: Two matching cycles of size about N^(1.5+eps)
    """
    n = 2 ** n_bits

    max_thresh = 7.389 * min_thresh  # e^2 * min_thresh

    visited_nodes = defaultdict(bool)
    found = False
    cycle_seed = 0

    sum_failed = 0

    while not found:
        # Create a random unvisited starting point
        while True:
            cycle_seed += 1
            sha = hashlib.sha256()
            sha.update((str(batch_id) + "$" + str(test_id) + "$" + str(cycle_seed) + "left").encode('utf-8'))
            left = int(sha.hexdigest(), 16) & (n - 1)
            sha = hashlib.sha256()
            sha.update((str(batch_id) + "$" + str(test_id) + "$" + str(cycle_seed) + "right").encode('utf-8'))
            right = int(sha.hexdigest(), 16) & (n - 1)
            if not visited_nodes[(left, right)]:
                break

        u_chain = [(left, right)]
        chain_len = 1
        visited_nodes[(left, right)] = True

        next_node = ff3.encrypt(u_chain[0], key, t_l, t_r, n_bits, n_bits, 8)
        query_table[(u_chain[0][0], u_chain[0][1])] = True
        while next_node != u_chain[0]:
            u_chain.append(next_node)
            chain_len += 1
            visited_nodes[next_node] = True
            next_node = ff3.encrypt(u_chain[-1], key, t_l, t_r, n_bits, n_bits, 8)
            query_table[(u_chain[-1][0], u_chain[-1][1])] = True

        if min_thresh <= chain_len <= max_thresh:
            target_len = chain_len
            found = True

        sum_failed += chain_len
        if sum_failed == n ** 2:
            return None, None
    visited_nodes = defaultdict(bool)
    found = False

    # Find the equivalent chain using the slid tweak
    while not found:
        # Create a random unvisited starting point
        while True:
            cycle_seed += 1
            sha = hashlib.sha256()
            sha.update((str(batch_id) + "$" + str(test_id) + "$" + str(cycle_seed) + "left").encode('utf-8'))
            left = int(sha.hexdigest(), 16) & (n - 1)
            sha = hashlib.sha256()
            sha.update((str(batch_id) + "$" + str(test_id) + "$" + str(cycle_seed) + "right").encode('utf-8'))
            right = int(sha.hexdigest(), 16) & (n - 1)
            if not visited_nodes[(left, right)]:
                break

        v_chain = [(left, right)]
        chain_len = 1
        visited_nodes[(left, right)] = True

        next_node = ff3.encrypt(v_chain[0], key, t_l ^ 4, t_r ^ 4, n_bits, n_bits, 8)
        query_table[(v_chain[0][0], u_chain[0][1])] = True
        while next_node != v_chain[0]:
            v_chain.append(next_node)
            chain_len += 1
            visited_nodes[next_node] = True
            next_node = ff3.encrypt(v_chain[-1], key, t_l ^ 4, t_r ^ 4, n_bits, n_bits, 8)
            query_table[(v_chain[-1][0], v_chain[-1][1])] = True

        if chain_len == target_len:
            found = True

    return u_chain, v_chain


def cycle_slide(u_chain, v_chain, n_bits, cycle_len, mu, key, t_l, t_r):
    """
    Given two chains, slide them against each other until reconstruction is successful
    :param u_chain: chain cycle of type g(f())
    :param v_chain: chain cycle of type f(g()) of the same length
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_len: Length of cycles in reconstruction attack
    :param mu: Number of times to attempt round function restoration
    :param key, t_l, t_r: Parameters for encryption
    :return: 8-round FF3 codebook if succeeded, None if failed
        Also returns separate success rates of distinguisher and codebook reconstruction
    """
    n = 2 ** n_bits

    chain_len = len(u_chain)

    # For testing
    reconstruction_success = 0
    reconstruction_fail = 0
    combined_rec_success = 0
    combined_rec_fail = 0
    true_pos = 0
    true_neg = 0
    false_pos = 0
    false_neg = 0

    # Preprocess the last q blocks of u_chain
    t = math.log(num_bins, n) / 4
    bins = process([(u_chain[i], i) for i in range(chain_len - q, chain_len)], n_bits, t)

    # Try reconstruction for each slide distance
    for i in range(len(u_chain)):
        # Check that it is a slid pair
        if dist(bins, v_chain, -i, n_bits, delta):
            if encryption_oracle(u_chain[i], v_chain[0], key, t_l, t_r, n_bits, 4):
                true_pos += 1

                f_x_chain = []
                f_y_chain = []
                g_x_chain = []
                g_y_chain = []

                for j in range(p, 2 * p):
                    f_x_chain.append(u_chain[j % chain_len])
                for j in range(p - i, 2 * p - i):
                    f_y_chain.append(v_chain[j % chain_len])
                for j in range(0, p):
                    g_x_chain.append(v_chain[j % chain_len])
                for j in range(i + 1, i + p + 1):
                    g_y_chain.append(u_chain[j % chain_len])

                f_x_chain = np.array(f_x_chain)
                f_y_chain = np.array(f_y_chain)
                g_x_chain = np.array(g_x_chain)
                g_y_chain = np.array(g_y_chain)

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

        elif encryption_oracle(u_chain[i], v_chain[0], key, t_l, t_r, n_bits, 4):
            false_neg += 1
        else:
            true_neg += 1
    return None, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos, false_neg


def slide_attack(n_bits, cycle_len, mu, batch_id, test_id):
    """
    Run the slide attack on random parameters
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_len: Length of cycles in cycle_finder attack
    :param mu: Number of times to attempt round function restoration
    :param batch_id: ID of current test batch
    :param test_id: ID of current test
    :return: 8-round FF3 codebook if succeeded, None if failed
    """
    # For testing
    query_table = {}

    key, t_l, t_r = key_init(n_bits, batch_id, test_id)

    u_chain, v_chain = make_cycle_chains(n_bits, key, t_l, t_r, batch_id, test_id, query_table)

    if u_chain is None or v_chain is None:
        return None, 0, 0, 0, 0, 0, 0, 0, 0, 1, len(query_table.keys())

    c, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos, \
    false_neg = cycle_slide(u_chain, v_chain, n_bits, cycle_len, mu, key, t_l, t_r)

    if c is not None:
        success = codebook_oracle(c, key, t_l, t_r, n_bits, 8)
        return success, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, \
               true_pos, true_neg, false_pos, false_neg, 0, len(query_table.keys())
        return c    # This is the full codebook reconstructed by the attack
    return None, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos, false_neg, 0, len(query_table.keys())


if __name__ == "__main__":
    n_bits = int(sys.argv[1])
    cycle_len = int(sys.argv[2])
    mu = int(sys.argv[3])
    num_bins = int(float(sys.argv[4]))  # Number of bins to use in the distinguisher
    t_flag = int(sys.argv[5])   # Unused
    batch_id = int(sys.argv[6])
    test_id = int(sys.argv[7])

    n = 2 ** n_bits

    start = time.time()

    # Global Parameters
    eps = 1 / (2 * cycle_len)
    p = int((2 ** (1. / 3)) * (n ** (1.5 + eps)))  # The length needed for codebook reconstruction
    q = int(n * (10/num_bins * n * n_bits) ** 0.5)  # The length needed for the distinguisher

    min_thresh = max(p, q)

    delta = 1.6 / n  # Threshold for the distinguisher

    success, reconstruction_success, reconstruction_fail, combined_rec_success, combined_rec_fail, true_pos, true_neg, false_pos, \
            false_neg, cycle_fail, num_queries = slide_attack(n_bits, cycle_len, mu, batch_id, test_id)
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
    print(cycle_fail)
    print(num_queries)
    print(end - start)
