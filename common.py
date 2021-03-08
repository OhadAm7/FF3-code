"""
Common functions used in the attacks
"""

import numpy as np
import ff3
from collections import defaultdict
import hashlib
import prf_reconstruction


def key_init(n_bits, batch_id, test_id):
    """
    Initialize random key and tweaks
    :param n_bits: Half the bit size of the encryption domain
    :param batch_id: ID of current test batch
    :param test_id: ID of current test
    :return: key: Encryption key
        t_l: Left tweak
        t_r: Right tweak
    """
    n = 2 ** n_bits

    sha = hashlib.sha256()
    sha.update((str(batch_id) + "$" + str(test_id) + "key").encode('utf-8'))
    key = int(sha.hexdigest(), 16) & ((2 ** 128) - 1)

    sha = hashlib.sha256()
    sha.update((str(batch_id) + "$" + str(test_id) + "t_l").encode('utf-8'))
    t_l = int(sha.hexdigest(), 16) & (n - 1)

    sha = hashlib.sha256()
    sha.update((str(batch_id) + "$" + str(test_id) + "t_r").encode('utf-8'))
    t_r = int(sha.hexdigest(), 16) & (n - 1)

    return key, t_l, t_r


def encryption_oracle(p, c, key, t_l, t_r, n_bits, rounds):
    """
    For testing, returns True if c is an encryption of p and False otherwise
    :param p: Plaintext
    :param c: Ciphertext
    :param key: Encryption key
    :param t_l: Left tweak
    :param t_r: Right tweak
    :param n_bits: Half the bit size of the encryption domain
    :param rounds: Number of encryption rounds
    :return: True or False
    """
    if np.all(ff3.encrypt(p, key, t_l, t_r, n_bits, n_bits, rounds) == c):
        return True
    return False


def codebook_oracle(codebook, key, t_l, t_r, n_bits, rounds):
    """
    For testing, uses 10 plaintext-ciphertext pairs to verify codebook
    :param codebook: Candidate codebook for FF3
    :param key: Encryption key
    :param t_l: Left tweak
    :param t_r: Right tweak
    :param n_bits: Half the bit size of the encryption domain
    :param rounds: Number of encryption rounds
    :return: True if the codebook is correct, False otherwise
    """
    if codebook is None:
        return False
    for right in range(10):
        ciphertext = ff3.encrypt((0, right), key, t_l, t_r, n_bits, n_bits, rounds)
        if ((ciphertext[0] << n_bits) + ciphertext[1]) != codebook[right]:
            return False
    return True


def make_chains(num_chains, half_chain_len, p, n_bits, key, t_l, t_r, batch_id, test_id, query_table):
    """
    Construct chains for the slide attack
    :param chains: Empty array for the chains to be stored in
    :param num_chains: Number of chains to make
    :param half_chain_len: Half the length of a chain
    :param n_bits: Half the bit size of the encryption domain
    :param key: Encryption key
    :param t_l: Left tweak
    :param t_r: Right tweak
    :param batch_id: ID of current test batch
    :param test_id: ID of current test
    :param query_table: Used to track oracle queries
    :return: List of chains
    """
    n = 2 ** n_bits

    chains = np.zeros((num_chains, 2 * half_chain_len + 1, 2), dtype=np.int32)

    for i in range(num_chains):
        chain_added = False
        unadded = 0
        chain_seed = 0

        while not chain_added:
            pairs_dic = defaultdict(list)
            # Make a random chain header
            sha = hashlib.sha256()
            sha.update((str(batch_id) + "$" + str(test_id) + "$" + str(i) + "$" + str(chain_seed)
                        + "left" + str(t_l)).encode('utf-8'))
            left = int(sha.hexdigest(), 16) & (n - 1)
            sha = hashlib.sha256()
            sha.update((str(batch_id) + "$" + str(test_id) + "$" + str(i) + "$" + str(chain_seed)
                        + "right" + str(t_l)).encode('utf-8'))
            right = int(sha.hexdigest(), 16) & (n - 1)
            chain_seed += 1

            chains[i][0] = np.array([left, right], dtype=np.int32)
            pairs_dic[right].append((chains[i][0], 0))

            # We take the pairs only from the first half of the chain
            for j in range(1, 2 * half_chain_len + 1):
                chains[i][j] = ff3.encrypt(chains[i][j - 1], key, t_l, t_r, n_bits, n_bits, 8)
                query_table[(chains[i][j - 1][0], chains[i][j - 1][1])] = True

            # Make sure that the chain doesn't loop
            is_distinct = True
            if unadded < 10:
                # Only the first p and the first half of the chain need not to loop
                for j in range(1, min(max(half_chain_len, p), 2 * half_chain_len + 1)):
                    # Enough to check only head of chain, because encryption is a permutation
                    if np.all(chains[i][j] == chains[i][0]):
                        is_distinct = False
                        unadded += 1
                        break
            else:
                return None
            if is_distinct:
                chain_added = True

    return chains


def extend_chain(chain, new_len, n_bits, key, t_l, t_r, query_table):
    """
    Extend a chain and verify that the first half doesn't loop
    :param chain: Chain to extend
    :param new_len: New length of chain
    :param n_bits: Half the bit size of the encryption domain
    :param key: Encryption key
    :param t_l: Left tweak
    :param t_r: Right tweak
    :param query_table: Used to track oracle queries
    :return: Extended chain
    """
    old_len = len(chain)
    if old_len > new_len:
        return chain
    new_chain = np.zeros((new_len, 2), dtype=np.int32)
    for i in range(old_len):
        new_chain[i] = chain[i]
    for i in range(old_len, new_len):
        new_chain[i] = ff3.encrypt(new_chain[i - 1], key, t_l, t_r, n_bits, n_bits, 8)
        query_table[(new_chain[i - 1][0], new_chain[i - 1][1])] = True

    # Make sure that the chain doesn't loop
    for j in range(1, int(new_len / 2)):
        # Enough to check only head of chain, because encryption is a permutation
        if np.all(new_chain[j] == new_chain[0]):
            return None
    return new_chain


def process(plaintexts, n_bits, t=0.25):
    """
    Preprocess plaintexts to be grouped according to right-hand-side, along with their original indices
    :param plaintexts: List of (plaintext, i), where i is the original index of plaintext
    :param n_bits: Half the bit size of the encryption domain
    :param t: Parameter for the time-data tradeoff
    :return: bins: List of lists of plaintexts with common right-hand-side, along with indices
    """
    n = 2 ** n_bits

    num_bins = int(round(n ** (4 * t)))

    partitions = defaultdict(list)

    for x, r in plaintexts:
        partitions[x[1]].append((x, r))
    partition_list = [partition for key, partition in partitions.items()]
    partition_list.sort(key=len, reverse=True)

    # Gather plaintexts from the bins, prioritizing the largest bins (if t=0, then only one bin is used)
    bins = []
    for i in range(min(num_bins, len(partition_list))):
        curr_bin = []
        for x, r in partition_list[i]:
            curr_bin.append((x, r))
        bins.append(curr_bin)
    return bins


def dist(bins, cipher_list, k, n_bits, delta):
    """
    Run distinguisher on preprocessed list
    :param bins: list of lists of plaintexts with common right-hand-side, along with original indices
    :param cipher_list: List of all ciphertexts according to original index
    :param k: Slide amount
    :param n_bits: Half the bit size of the encryption domain
    :param delta: Threshold for the distinguisher
    :return: Result of distinguisher
    """
    n = 2 ** n_bits

    count = 0
    size = sum([(len(bin) * (len(bin) - 1) / 2) for bin in bins])

    for i in range(len(bins)):
        group_count = 0
        table = defaultdict(int)
        for pair in bins[i]:
            diff = (cipher_list[pair[1] + k][0] - pair[0][0]) % n
            table[diff] += 1
        for diff, value in table.items():
            group_count += (value * (value - 1) / 2)
        count += group_count

    if count >= delta * size:
        return True
    return False


def reconstruct(x_chain, y_chain, n_bits, cycle_len, mu):
    """
    Using a slid chain pair, reconstruct the full encryption codebook
    :param x_chain: Plaintext list
    :param y_chain: Ciphertext list
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_len: Length of cycles in cycle_finder attack
    :param mu: Number of times to attempt round function restoration
    :return: 4-round FF3 codebook (of both halves) if succeeded, None if failed
    """
    n = 2 ** n_bits

    round_funcs = prf_reconstruction.reconstruction_attack(x_chain, y_chain, n_bits, cycle_len, mu)
    if round_funcs is None:
        return None
    else:
        pass
    f_0, f_1, f_2, f_3 = round_funcs
    round_f = [f_0, f_1, f_2, f_3]
    f = []
    for i in range(n):
        for j in range(n):
            left = i
            right = j
            # Calculate FF3 on (i, j) using the round functions
            for k in range(4):
                if (k % 2) == 0:
                    left = (left + round_f[k][right]) % n
                else:
                    right = (right + round_f[k][left]) % n
            f.append((left << n_bits) + right)
    return f
