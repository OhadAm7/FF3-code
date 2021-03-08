import sys
from statistics import median

if __name__ == "__main__":
    attack_id = int(sys.argv[1])    # 1 if symmetric attack, 2 if cycle structure attack, 3 if asymmetric attack
    n_bits = int(sys.argv[2])
    cycle_len = int(sys.argv[3])
    mu = int(sys.argv[4])
    t = float(sys.argv[5])
    t_flag = int(sys.argv[6])
    batch_id = int(sys.argv[7])
    k = int(sys.argv[8])    # Sample size of experiment

    success_count = 0
    sum_reconstruction_success = 0
    sum_reconstruction_fail = 0
    sum_combined_success = 0
    sum_combined_fail = 0
    sum_true_pos = 0
    sum_true_neg = 0
    sum_false_pos = 0
    sum_false_neg = 0
    false_positives = []
    sum_cycle_fail = 0
    sum_queries = 0
    arr_queries = []
    sum_suc_queries = 0
    arr_suc_queries = []
    sum_time = 0
    times = []

    if attack_id == 1:
        attack_name = "symmetric_attack"
    if attack_id == 2:
        attack_name = "cycle_structure_attack"
    if attack_id == 3:
        attack_name = "asymmetric_attack"

    for i in range(k):
        f = open(attack_name + "." + str(n_bits) + "." + str(cycle_len) + "." + str(mu) + "." + str(t) + "." +
                 str(t_flag) + "." + str(batch_id) + "." + str(i) + ".out", "r")

        success = int(f.readline())
        reconstruction_success = int(f.readline())
        reconstruction_fail = int(f.readline())
        combined_success = int(f.readline())
        combined_fail = int(f.readline())
        true_pos = int(f.readline())
        true_neg = int(f.readline())
        false_pos = int(f.readline())
        false_neg = int(f.readline())
        if attack_id == 2:
            cycle_fail = int(f.readline())
        queries = int(f.readline())
        time = float(f.readline())

        if success:
            success_count += 1
            sum_suc_queries += queries
            arr_suc_queries.append(queries)
        sum_reconstruction_success += reconstruction_success
        sum_reconstruction_fail += reconstruction_fail
        sum_combined_success += combined_success
        sum_combined_fail += combined_fail
        sum_true_pos += true_pos
        sum_true_neg += true_neg
        sum_false_pos += false_pos
        false_positives.append(false_pos)
        sum_false_neg += false_neg
        sum_queries += queries
        arr_queries.append(queries)
        sum_time += time
        times.append(time)
        if attack_id == 2:
            sum_cycle_fail += cycle_fail

        f.close()

    if sum_reconstruction_success + sum_reconstruction_fail == 0:
        reconstruction_rate = -1
        combined_rate = -1
    else:
        reconstruction_rate = float(sum_reconstruction_success) / (sum_reconstruction_success + sum_reconstruction_fail)
        combined_rate = float(sum_combined_success) / (sum_combined_success + sum_combined_fail)
    if attack_id == 3:
        dist_rate = float(sum_true_pos) / (sum_true_pos + sum_true_neg + sum_false_pos + sum_false_neg)
    else:
        dist_rate_cipher = float(sum_true_pos) / (sum_true_pos + sum_false_neg)
        dist_rate_rand = float(sum_true_neg) / (sum_true_neg + sum_false_pos)
    average_false_positives = sum_false_pos / k
    median_false_positives = median(false_positives)
    average_queries = sum_queries / k
    median_queries = median(arr_queries)
    if success_count == 0:
        average_suc_queries = -1
        median_suc_queries = -1
    else:
        average_suc_queries = sum_suc_queries / success_count
        median_suc_queries = median(arr_suc_queries)
    average_time = sum_time / k
    median_time = median(times)
    if attack_id == 2:
        cycle_fail_rate = sum_cycle_fail / k

    print("Success Count:", success_count)
    if attack_id == 2:
        print("Cycle Fail Rate:", cycle_fail_rate)
    print("Reconstruction Rate:", reconstruction_rate)
    print("Reconstruction Sample Size:", sum_reconstruction_success + sum_reconstruction_fail)
    print("Combined Reconstruction Rate:", combined_rate)
    if attack_id == 3:
        print("Distinguisher Success Rate:", dist_rate)
        print("Distinguisher Sample Size:", sum_true_pos + sum_false_neg + sum_false_pos + sum_false_neg)
    else:
        print("Distinguisher Success Rate (Cipher):", dist_rate_cipher)
        print("Distinguisher Sample Size (Cipher):", sum_true_pos + sum_false_neg)
        print("Distinguisher Success Rate (Rand):", dist_rate_rand)
        print("Distinguisher Sample Size (Rand):", sum_false_pos + sum_true_neg)
    print("False Positives (Average):", average_false_positives)
    print("False Positives (Median):", median_false_positives)
    print("Queries (Average):", average_queries)
    print("Queries (Median):", median_queries)
    print("Queries Successful (Average):", average_suc_queries)
    print("Queries Successful (Median):", median_suc_queries)
    print("Time (Average):", average_time)
    print("Time (Median):", median_time)
