"""
Generate a LaTeX file of a table containing the results of an experiment
"""

import sys

attack_id = int(sys.argv[1])  # 1 if symmetric attack, 2 if cycle structure attack, 3 if asymmetric attack
n_bits_min = int(sys.argv[2])
n_bits_max = int(sys.argv[3])
cycle_len_min = int(sys.argv[4])
cycle_len_max = int(sys.argv[5])
mu = int(sys.argv[6])
t = float(sys.argv[7])
t_flag = int(sys.argv[8])
batch_id = int(sys.argv[9])
k = int(sys.argv[10])

if attack_id == 1:
    attack_name = "symmetric_attack"
    caption = "Symmetric Slide Attack Experiment Results"
    if t_flag:
        caption = caption + " ($num\;bins = " + str(t) + "$)"
    else:
        caption = caption + " ($t = " + str(t) + "$)"
if attack_id == 2:
    attack_name = "cycle_structure_attack"
    caption = "Cycle Structure Attack Experiment Results ($num\;bins = " + str(t) + "$)"
if attack_id == 3:
    attack_name = "asymmetric_attack"
    caption = "Asymmetric Slide Attack Experiment Results"
    if t_flag:
        caption = caption + " ($num\;ciphertext\;chains = " + str(t) + "$)"
    else:
        caption = caption + " ($t = " + str(t) + "$)"

print("""\\documentclass[8pt]{extarticle}

\\usepackage[margin=0.0in]{geometry}

\\begin{document}
\\begin{table}
\t\\begin{center}""")

if attack_id == 3:
    print("\t\t\\begin{tabular}{||c c || c | c | c | c | c ||}")
else:
    print("\t\t\\begin{tabular}{||c c || c | c | c | c | c | c ||}")

print("\t\t\t\\hline")

if attack_id == 3:
    print("""\t\t\t$N$ & $L$ & Queries & Success & PRF & Combined & Distinguisher \\\\
\t\t\t& & & Rate & Reconstruction & Reconstruction & Success Rate \\\\ [0.5ex]""")
else:
    print("""\t\t\t$N$ & $L$ & Queries & Success & PRF Reconstruction & Combined & Distinguisher & Distinguisher \\\\
\t\t\t& & & Rate & & Reconstruction & (Cipher) & (Rand) \\\\ [0.5ex] """)

print("\t\t\t\\hline\\hline")

for cycle_len in range(cycle_len_min, cycle_len_max + 1):
    for n_bits in range(n_bits_min, n_bits_max + 1):
        dir_name = attack_name + "-results." + str(n_bits) + "." + str(cycle_len) + "." + str(mu) + "." + str(t) + "." \
                   + str(t_flag) + "." + str(batch_id)
        file_name = dir_name + ".txt"
        f = open(dir_name + "/" + file_name)

        success_rate = str(round(float(f.readline().split()[-1]) / 100, 2))
        if attack_id == 2:
            cycle_fail_rate = str(round(float(f.readline().split()[-1]), 3))
        reconstruction_rate = str(round(float(f.readline().split()[-1]), 3))
        reconstruction_sample = f.readline().split()[-1]
        combined_rate = str(round(float(f.readline().split()[-1]), 3))
        if attack_id == 3:
            dist_rate = str(round(float(f.readline().split()[-1]), 3))
            dist_sample = f.readline().split()[-1]
        else:
            dist_rate_cipher = str(round(float(f.readline().split()[-1]), 3))
            dist_sample_cipher = f.readline().split()[-1]
            dist_rate_rand = str(round(float(f.readline().split()[-1]), 3))
            dist_sample_rand = f.readline().split()[-1]
        false_pos_avg = str(round(float(f.readline().split()[-1]), 3))
        false_pos_med = str(round(float(f.readline().split()[-1]), 3))
        queries_avg = str(round(float(f.readline().split()[-1])))
        queries_med = str(round(float(f.readline().split()[-1])))
        queries_suc_avg = str(round(float(f.readline().split()[-1])))
        queries_suc_med = str(round(float(f.readline().split()[-1])))
        time_avg = str(round(float(f.readline().split()[-1]), 3))
        time_med = str(round(float(f.readline().split()[-1]), 3))

        if attack_id == 3:
            print("\t\t\t$2^{" + str(n_bits) + "}$ & " + str(cycle_len) + " & " + queries_med + " & " + success_rate +
                  " & " + reconstruction_rate + " & " + combined_rate + " & " + dist_rate + " \\\\\n\t\t\t\\hline")
        else:
            print("\t\t\t$2^{" + str(n_bits) + "}$ & " + str(cycle_len) + " & " + queries_med + " & " + success_rate +
                  " & " + reconstruction_rate + " & " + combined_rate + " & " + dist_rate_cipher + " & " +
                  dist_rate_rand + " \\\\\n\t\t\t\\hline")

        f.close()
    print("\t\t\t\\hline")
print("""\t\t\\end{tabular}
\t\\end{center}
\\caption{""" + caption + """}
\\end{table}
\\end{document}""")
