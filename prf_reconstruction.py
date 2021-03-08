"""
Subroutine for reconstructing the codebooks of FF3 round functions - Section 4.4
"""

import math
import time
from collections import defaultdict
import copy
import ff3
import sys
import hashlib
import numpy as np


def construct_nodes(plaintexts, ciphertexts, n):
    """
    Constructs the nodes of the graph.
    :param plaintexts: List of p plaintexts
    :param ciphertexts: List of p ciphertexts
    :param n: Domain size of half of the encryption
    :return: A list of all possible nodes defined by plaintexts, ciphertexts, with no duplicates
    """
    node_finder = defaultdict(list)

    # Makes a node of each pair (xyzt), (x'y'z't') such that z = z', t-y = t'-y', xy != x'y'
    for i in range(len(plaintexts)):
        x = plaintexts[i][0]
        y = plaintexts[i][1]
        z = ciphertexts[i][0]
        t = ciphertexts[i][1]
        half_node = (x, y, z, t)
        half_node_key = (z, (t - y) % n)
        node_finder[half_node_key].append(half_node)

    node_list = []
    for pair_list in node_finder.values():
        for i in pair_list:
            for j in pair_list:
                if i != j:
                    node_list.append((i, j, (i[0] - j[0]) % n))

    return node_list


def construct_edges(nodelist, debug):
    """
    Given a list of nodes, constructs the relevant edges - an edge (x1y1x1'y1', x2y2x2'y2') exists if y1' = y2.
    :param nodelist: List of nodes
    :param debug: True if print statements are to be made
    :return: outgoing: Dictionary from each node to its neighbors (outgoing)
            incoming: Dictionary from each node to its neighbors (incoming)
    """
    edge_finder = {}
    for node in nodelist:
        y = node[0][1]
        y_tag = node[1][1]

        # Add node to list of potential start nodes
        if y in edge_finder.keys():
            edge_finder[y][1].append(node)
        else:
            edge_finder[y] = [[], [node]]

        # Add node to list of potential end nodes
        if y_tag in edge_finder.keys():
            edge_finder[y_tag][0].append(node)
        else:
            edge_finder[y_tag] = [[node], []]

    # For testing
    num_edges = 0

    # Construct edges
    outgoing = defaultdict(list)
    incoming = defaultdict(list)
    for y in edge_finder.keys():
        for start_node in edge_finder[y][0]:
            for end_node in edge_finder[y][1]:
                if end_node != start_node:
                    outgoing[start_node].append(end_node)  # Add to list of outgoing edges from start_node
                    incoming[end_node].append(start_node)  # Add to list of incoming edges to end_node

                    # For testing
                    num_edges += 1

    if debug:
        print(num_edges)

    return outgoing, incoming


def make_graph(plaintexts, ciphertexts, n_bits, f0_oracle=(), debug=False):
    """
    Constructs a graph out of (P, C) pairs
    :param plaintexts: List of p plaintexts
    :param ciphertexts: List of p ciphertexts
    :param n_bits: Half the bit size of the encryption domain
    :param f0_oracle: Codebook of first round (used only for testing)
    :param debug: True if print statements are to be made (use only if f0_oracle is also given)
    :return: outgoing: Dictionary from each node to its neighbors (outgoing)
            incoming: Dictionary from each node to its neighbors (incoming)
    """
    n = 2 ** n_bits

    nodes = construct_nodes(plaintexts, ciphertexts, n)

    # For testing
    if debug:
        num_good_nodes = 0
        for node in nodes:
            if is_good(node, f0_oracle, n):
                num_good_nodes += 1
        print(len(nodes))
        print(num_good_nodes)

    outgoing, incoming = construct_edges(nodes, debug)
    return outgoing, incoming


def is_bad_cycle(cycle):
    """
    Checks if a triangles nodes have common messages
    :param cycle: Cycle
    :return: True if there are common messages, False if there aren't.
    """
    messages = []
    for node in cycle:
        for i in range(2):
            if node[i] in messages:
                return True
            messages.append(node[i])
    return False


def normalize_cycle(cycle):
    """
    Normalizes a cycle such that the first node is the one with the smallest message
    :param cycle: A cycle
    :param n_bits: Half the bit size of the encryption domain
    :return: Normalized cycle
    """
    cycle_len = len(cycle)
    nodes = list(enumerate(cycle))
    node_val = lambda x: x[1]
    min_node = min(nodes, key=node_val)[0]
    normalized = [cycle[(min_node + i) % cycle_len] for i in range(cycle_len)]
    return tuple(normalized)


def recursive_cycle_finder(outgoing, node, len):
    """
    Perform partial DFS on graph
    :param outgoing: Dictionary from each node to its neighbors (outgoing)
    :param node: Where to start search
    :param len: Length of remaining chain
    :return: List of all chains that begin with node
    """
    if len == 0:
        return [[node]]

    chains = []
    for neighbor in outgoing[node]:
        for chain in recursive_cycle_finder(outgoing, neighbor, len - 1):
            new_chain = [node] + chain
            chains.append(new_chain)
    return chains


# For testing
def count_all_triangles(graph):
    """
    Given a graph, finds all triangles in it where the sum of labels is 0.
    :param graph: outgoing: Dictionary from each node to its neighbors (outgoing)
            incoming: Dictionary from each node to its neighbors (incoming)
    :return: Number of triangles, where each triangle is a tuple of 3 nodes
    """
    outgoing = graph[0]
    incoming = graph[1]

    triangle_table = defaultdict(bool)

    # Perform MITM to find triangles
    for start_node in outgoing.keys():
        in_path = defaultdict(bool)

        for end_node in incoming[start_node]:
            in_path[end_node] = True

        for mid_node in outgoing[start_node]:
            for end_node in outgoing[mid_node]:
                if in_path[end_node]:
                    triangle = (start_node, end_node, mid_node)
                    if not is_bad_cycle(triangle):
                        triangle_table[normalize_cycle(triangle)] = True

    triangle_count = 0
    for triangle in triangle_table.keys():
        triangle_count += 1
    return triangle_count


# For testing
def count_all_squares(graph):
    """
    Given a graph, finds all squares in it where the sum of labels is 0.
    :param graph: outgoing: Dictionary from each node to its neighbors (outgoing)
            incoming: Dictionary from each node to its neighbors (incoming)
    :return: Number of squares, where each square is a tuple of 4 nodes
    """
    outgoing = graph[0]
    incoming = graph[1]

    square_table = defaultdict(bool)

    # Perform MITM to find squares of type (u, v, w, t)
    for u in outgoing.keys():
        in_path = defaultdict(list)

        for t in incoming[u]:
            for w in incoming[t]:
                in_path[w].append(t)

        for v in outgoing[u]:
            for w in outgoing[v]:
                for t in in_path[w]:
                    square = (u, v, w, t)
                    if not is_bad_cycle(square):
                        square_table[normalize_cycle(square)] = True

    square_count = 0
    for square in square_table.keys():
        square_count += 1
    return square_count


# For testing
def count_all_pentagons(graph):
    """
    Given a graph, finds all pentagons in it where the sum of labels is 0.
    :param graph: outgoing: Dictionary from each node to its neighbors (outgoing)
            incoming: Dictionary from each node to its neighbors (incoming)
    :return: Number of pentagons, where each pentagon is a tuple of 5 nodes
    """
    outgoing = graph[0]
    incoming = graph[1]

    pentagon_table = defaultdict(bool)

    # Perform MITM to find pentagons of type (u, v, w, t, z)
    for u in outgoing.keys():
        in_path = defaultdict(list)

        for z in incoming[u]:
            for t in incoming[z]:
                in_path[t].append(z)

        for v in outgoing[u]:
            for w in outgoing[v]:
                for t in outgoing[w]:
                    for z in in_path[t]:
                        pentagon = (u, v, w, t, z)
                        if not is_bad_cycle(pentagon):
                            pentagon_table[normalize_cycle(pentagon)] = True

    pentagon_count = 0
    for pentagon in pentagon_table.keys():
        pentagon_count += 1
    return pentagon_count


# For testing
def count_all_cycles(graph, cycle_len):
    """
    Counts all size L cycles in the graph
    :param graph: outgoing: Dictionary from each node to its neighbors (outgoing)
            incoming: Dictionary from each node to its neighbors (incoming)
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_len: Size of cycles to be found
    :return: Number of cycles, where each cycle is a tuple of L nodes
    """
    if cycle_len == 3:
        return count_all_triangles(graph)
    if cycle_len == 4:
        return count_all_squares(graph)
    if cycle_len == 5:
        return count_all_pentagons(graph)


def get_triangles(graph, n_bits):
    """
    Given a graph, finds all triangles in it where the sum of labels is 0.
    :param graph: outgoing: Dictionary from each node to its neighbors (outgoing)
            incoming: Dictionary from each node to its neighbors (incoming)
    :param n_bits: Half the bit size of the encryption domain
    :return: List of triangles, where each triangle is a tuple of 3 nodes
    """
    n = 2 ** n_bits
    outgoing = graph[0]
    incoming = graph[1]

    triangle_table = defaultdict(bool)

    # Perform MITM to find triangles
    for start_node in outgoing.keys():
        in_path = defaultdict(bool)

        for end_node in incoming[start_node]:
            label = (0 - end_node[2]) % n
            in_path[(end_node, label)] = True

        for mid_node in outgoing[start_node]:
            label = (start_node[2] + mid_node[2]) % n
            for end_node in outgoing[mid_node]:
                if in_path[(end_node, label)]:
                    triangle = (start_node, end_node, mid_node)
                    if not is_bad_cycle(triangle):
                        triangle_table[normalize_cycle(triangle)] = True

    triangles = []
    for triangle in triangle_table.keys():
        triangles.append(triangle)
    return triangles


def get_squares(graph, n_bits):
    """
    Given a graph, finds all squares in it where the sum of labels is 0.
    :param graph: outgoing: Dictionary from each node to its neighbors (outgoing)
            incoming: Dictionary from each node to its neighbors (incoming)
    :param n_bits: Half the bit size of the encryption domain
    :return: List of squares, where each square is a tuple of 4 nodes
    """
    n = 2 ** n_bits
    outgoing = graph[0]
    incoming = graph[1]

    square_table = defaultdict(bool)

    # Perform MITM to find squares of type (u, v, w, t)
    for u in outgoing.keys():
        in_path = defaultdict(list)

        for t in incoming[u]:
            for w in incoming[t]:
                label = (0 - t[2] - w[2]) % n
                in_path[(w, label)].append(t)

        for v in outgoing[u]:
            label = (u[2] + v[2]) % n
            for w in outgoing[v]:
                for t in in_path[(w, label)]:
                    square = (u, v, w, t)
                    if not is_bad_cycle(square):
                        square_table[normalize_cycle(square)] = True

    squares = []
    for square in square_table.keys():
        squares.append(square)
    return squares


def get_pentagons(graph, n_bits):
    """
    Given a graph, finds all pentagons in it where the sum of labels is 0.
    :param graph: outgoing: Dictionary from each node to its neighbors (outgoing)
            incoming: Dictionary from each node to its neighbors (incoming)
    :param n_bits: Half the bit size of the encryption domain
    :return: List of pentagons, where each pentagon is a tuple of 5 nodes
    """
    n = 2 ** n_bits
    outgoing = graph[0]
    incoming = graph[1]

    pentagon_table = defaultdict(bool)

    # Perform MITM to find pentagons of type (u, v, w, t, z)
    for u in outgoing.keys():
        in_path = defaultdict(list)

        for z in incoming[u]:
            for t in incoming[z]:
                label = (0 - z[2] - t[2]) % n
                in_path[(t, label)].append(z)

        for v in outgoing[u]:
            for w in outgoing[v]:
                label = (u[2] + v[2] + w[2]) % n
                for t in outgoing[w]:
                    for z in in_path[(t, label)]:
                        pentagon = (u, v, w, t, z)
                        if not is_bad_cycle(pentagon):
                            pentagon_table[normalize_cycle(pentagon)] = True

    pentagons = []
    for pentagon in pentagon_table.keys():
        pentagons.append(pentagon)
    return pentagons


def get_cycles(graph, n_bits, cycle_len):
    """
    Given a graph, finds all size L cycles in it where the sum of labels is 0.
    Note: cycle lengths above 5 broken, do not use
    :param graph: outgoing: Dictionary from each node to its neighbors (outgoing)
            incoming: Dictionary from each node to its neighbors (incoming)
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_len: Size of cycles to be found
    :return: List of cycles, where each cycle is a tuple of 3 nodes
    """
    if cycle_len == 3:
        return get_triangles(graph, n_bits)
    if cycle_len == 4:
        return get_squares(graph, n_bits)
    if cycle_len == 5:
        return get_pentagons(graph, n_bits)


def largest_connected_component(edges, n_bits):
    """
    Finds the largest connected component of the good_node graph
    :param edges: Dictionary from each vertex to its neighbors (outgoing)
    :param n_bits: Half the bit size of the encryption domain
    :return: A list of all the vertices in the largest component (y values of good nodes)
    """
    n = 2 ** n_bits
    visited = defaultdict(bool)

    max_component = []

    for i in range(n):
        # BFS
        component = []
        queue = [i]
        while len(queue):
            next = queue.pop(0)
            if not visited[next]:
                visited[next] = True
                component.append(next)
                for neighbor in edges[next]:
                    queue.append(neighbor)
        if len(component) > len(max_component):
            max_component = copy.copy(component)
    return max_component


def restore_3_rounds(plaintexts, ciphertexts, n_bits, iteration):
    """
    Given (P, C) pairs for 3 encryption rounds, restore the round function codebooks
    :param plaintexts: List of plaintexts
    :param ciphertexts: List of ciphertexts
    :param n_bits: Half the bit size of the encryption domain
    :return: (f_1, f_2, f_3): The round codebooks
    """
    n = 2 ** n_bits

    f_1 = [-1] * n
    f_2 = [-1] * n
    f_3 = [-1] * n

    plain_lists = defaultdict(list)
    cipher_lists = defaultdict(list)

    # Put all plaintexts and ciphertexts into hash tables
    for i in range(len(plaintexts)):
        plain_lists[plaintexts[i][1]].append((plaintexts[i], ciphertexts[i]))
        cipher_lists[ciphertexts[i][1]].append((plaintexts[i], ciphertexts[i]))

    # Anchor arbitrary starting point for f_1
    sha = hashlib.sha256()
    sha.update((str(plaintexts[0]) + "$" + str(iteration) + "3 rounds").encode('utf-8'))
    y_init = int(sha.hexdigest(), 16) & (n - 1)
    f_1[y_init] = 0

    s_1 = plain_lists[y_init]

    # Yoyo attack - alternatingly recover parts of f_1 and f_3
    while True:
        # Use all new s_1 data to recover parts of f_3
        s_2 = []
        for plaintext, ciphertext in s_1:
            if f_3[ciphertext[1]] == -1:
                c = (plaintext[0] + f_1[plaintext[1]]) % n
                f_3[ciphertext[1]] = (ciphertext[0] - c) % n
                s_2 += cipher_lists[ciphertext[1]]

        # Use all new s_2 data to recover parts of f_1
        s_1 = []
        for plaintext, ciphertext in s_2:
            if f_1[plaintext[1]] == -1:
                c = (ciphertext[0] - f_3[ciphertext[1]]) % n
                f_1[plaintext[1]] = (c - plaintext[0]) % n
                s_1 += plain_lists[plaintext[1]]

        # Stop when no new data is known
        if len(s_1) + len(s_2) == 0:
            break

    # Use f_1 and f_3 to recover f_2
    s_1 = [(plaintexts[i], ciphertexts[i]) for i in range(len(plaintexts)) if f_1[plaintexts[i][1]] != -1]
    for plaintext, ciphertext in s_1:
        f_2[(plaintext[0] + f_1[plaintext[1]]) % n] = (ciphertext[1] - plaintext[1]) % n

    return f_1, f_2, f_3


def restore_4_rounds(plaintexts, ciphertexts, graph, label_table, n_bits, iteration):
    """
    Using the good_node graph, reconstruct the round functions of 4-round encryption
    :param plaintexts: List of plaintexts
    :param ciphertexts: List of ciphertexts
    :param graph: largest connected good_node component
            (vertices, edges): vertices: List of vertices (y values of good nodes)
                            edges: Dictionary from each vertex to its neighbors (outgoing)
    :param label_table: Dictionary from each edge to its label
    :param n_bits: Half the bits of the encryption domain size
    :param iteration: Number of restoration attempt
    :return: (f_0, f_1, f_2, f_3): The round codebooks
    """
    n = 2 ** n_bits
    f_0 = [-1] * n

    vertices = graph[0]
    edges = graph[1]

    # Anchor arbitrary starting point for f_0
    sha = hashlib.sha256()
    sha.update((str(plaintexts[0]) + "$" + str(iteration) + "4 rounds").encode('utf-8'))
    x = vertices[int(sha.hexdigest(), 16) % len(vertices)]
    f_0[x] = 0

    # BFS
    visited = defaultdict(bool)
    visited[x] = True
    num_visited = 0
    queue = [(neighbor, x) for neighbor in edges[x]]

    # Calculate values for about sqrt(n) of f_0
    while len(queue) and num_visited <= (math.log(n, 2)/3) * math.sqrt(n):
        next, parent = queue.pop(0)
        if not visited[next]:
            visited[next] = True
            # Fill values of f_0
            f_0[next] = (f_0[parent] + label_table[(parent, next)]) % n
            num_visited += 1

            for neighbor in edges[next]:
                queue.append((neighbor, next))

    # Generate 3-round (P, C) pairs using known f_0 values
    plaintexts_3 = []
    ciphertexts_3 = []
    for i, plaintext in enumerate(plaintexts):
        if f_0[plaintext[1]] != -1:
            plaintexts_3.append((plaintext[1], (plaintext[0] + f_0[plaintext[1]]) % n))
            ciphertexts_3.append((ciphertexts[i][1], ciphertexts[i][0]))

    f_1, f_2, f_3 = restore_3_rounds(plaintexts_3, ciphertexts_3, n_bits, iteration)

    # Use the recovered codebooks to recover the rest of f_0
    for i, plaintext in enumerate(plaintexts):
        ciphertext = ciphertexts[i]
        if f_0[plaintext[1]] == -1:
            c = (ciphertext[0] - f_2[(ciphertext[1] - f_3[ciphertext[0]]) % n]) % n
            f_0[plaintext[1]] = (c - plaintext[0]) % n

    return f_0, f_1, f_2, f_3


# For testing
def is_good(node, f0_oracle, n):
    if (node[0][0] + f0_oracle[node[0][1]]) % n == (node[1][0] + f0_oracle[node[1][1]]) % n:
        return True
    return False


# For testing
def is_good_cycle(cycle, f0_oracle, n):
    for node in cycle:
        if not is_good(node, f0_oracle, n):
            return False
    return True


def reconstruction_attack(plaintexts, ciphertexts, n_bits, cycle_length, mu, f0_oracle=(), debug=False):
    """
    Attack on 4 rounds of FF3.
    :param plaintexts: List of p plaintexts
    :param ciphertexts: List of p ciphertexts
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_length: Length of cycles to be found
    :param mu: Number of times to attempt round function restoration
    :param f0_oracle: Codebook of first round (used only for testing)
    :param debug: True if print statements are to be made (use only if f0_oracle is also given)
    :return: (f_0, f_1, f_2, f_3) if successful, None if not.
    """
    n = 2 ** n_bits

    graph = make_graph(plaintexts, ciphertexts, n_bits, f0_oracle, debug)
    cycles = get_cycles(graph, n_bits, cycle_length)

    # For testing
    num_good_cycles = 0
    num_bad_cycles = 0

    # Gather all of the good nodes from triangles
    good_nodes_table = defaultdict(bool)
    for cycle in cycles:
        for good_node in cycle:
            good_nodes_table[good_node] = True
        if debug:
            if is_good_cycle(cycle, f0_oracle, n):
                num_good_cycles += 1
            else:
                num_bad_cycles += 1

    if debug:
        print(num_good_cycles)
        print(num_bad_cycles)

    # For testing
    num_false_good_nodes = 0

    good_nodes = []
    for node in good_nodes_table.keys():
        good_nodes.append(node)
        # For testing
        if debug and not is_good(node, f0_oracle, n):
            num_false_good_nodes += 1

    if debug:
        print(len(good_nodes))
        print(num_false_good_nodes)

    # Generate the good_node graph, and store relevant labels
    label_table = {}
    edges = defaultdict(list)
    for node in good_nodes:
        y = node[0][1]
        y_tag = node[1][1]
        edges[y].append(y_tag)
        label_table[(y, y_tag)] = node[2]

    # For testing
    missing_reconstruction = 0
    false_reconstruction = 0
    success_reconstruction = 0

    vertices = largest_connected_component(edges, n_bits)
    component = (vertices, edges)
    # Attempt restoration mu times (Each time using a random starting point)
    for i in range(mu):
        f_0, f_1, f_2, f_3 = restore_4_rounds(plaintexts, ciphertexts, component, label_table, n_bits, i)
        f = [f_0, f_1, f_2, f_3]
        # For testing
        missing = False
        for round_func in f:
            for j in round_func:
                if j == -1:
                    missing = True
        if missing:
            missing_reconstruction += 1

        # Verify that reconstruction was successful by calculating FF3 using f
        reconstructed = True
        for j in range(3 * n):
            left, right = plaintexts[j]
            for k in range(4):
                if (k % 2) == 0:
                    left = (left + f[k][right]) % n
                else:
                    right = (right + f[k][left]) % n

            if np.any(ciphertexts[j] != [left, right]):
                reconstructed = False
                break
        if reconstructed:
            success_reconstruction += 1
            if debug:
                print(success_reconstruction)
                print(missing_reconstruction)
                print(false_reconstruction)
            return f_0, f_1, f_2, f_3
        else:
            if not missing:
                false_reconstruction += 1
    if debug:
        print(success_reconstruction)
        print(missing_reconstruction)
        print(false_reconstruction)


# For testing
def run_reconstruction_attack(n_bits, cycle_length, mu, batch_id, test_id):
    """
    Run the attack on randomly generated data. For testing purposes.
    :param n_bits: Half the bit size of the encryption domain
    :param cycle_length: Length of cycles to be found
    :param mu: Number of times to attempt round function restoration
    :param batch_id: ID of current batch
    :param test_id: ID of current test
    :return: Attack result
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

    f0_oracle = np.zeros(n, dtype=np.int32)
    for i in range(n):
        f0_oracle[i] = (ff3.round_function(i, n, key, t_r))

    eps = 1/(2 * cycle_length)
    p = int((2 ** (1. / 3)) * (n ** (1.5 + eps)))

    plaintexts = np.zeros((p, 2), dtype=np.int32)
    ciphertexts = np.zeros((p, 2), dtype=np.int32)

    taken_texts = defaultdict(bool)
    for i in range(p):
        plaintext_seed = 0
        need_plaintext = True
        while need_plaintext:
            sha = hashlib.sha256()
            sha.update((str(batch_id) + "$" + str(test_id) + "$" + str(i) + "$" + str(plaintext_seed) + "p_left").encode('utf-8'))
            left = int(sha.hexdigest(), 16) & (n - 1)

            sha = hashlib.sha256()
            sha.update((str(batch_id) + "$" + str(test_id) + "$" + str(i) + "$" + str(plaintext_seed) + "p_right").encode('utf-8'))
            right = int(sha.hexdigest(), 16) & (n - 1)

            plaintext = (left, right)

            need_plaintext = taken_texts[plaintext]
            plaintext_seed += 1
        taken_texts[plaintext] = True

        ciphertext = ff3.encrypt(plaintext, key, t_l, t_r, n_bits, n_bits, 4)
        plaintexts[i] = plaintext
        ciphertexts[i] = ciphertext

    return reconstruction_attack(plaintexts, ciphertexts, n_bits, cycle_length, mu, f0_oracle, True)


if __name__ == "__main__":
    n_bits = int(sys.argv[1])
    cycle_length = int(sys.argv[2])
    mu = int(sys.argv[3])
    batch_id = int(sys.argv[4])
    test_id = int(sys.argv[5])

    start = time.time()

    run_reconstruction_attack(n_bits, cycle_length, mu, batch_id, test_id)

    end = time.time()
    print(end - start)
