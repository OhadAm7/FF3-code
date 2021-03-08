# FF3-code

Guide for generating data as presented in the paper.

Required Python libraries:
- sys
- time
- math
- copy
- collections
- numpy
- statistics
- hashlib
- Crypto 

## Running Experiments
Run:

run_attack.sh \<attack_id\> \<n_bits_min\> <\n_bits_max\> <\L_min\> <\L_max\> <\mu\> <\t> <\t_flag\> <\batch_id\> <\k\>
- attack_id - 1 for symmetric attack (section 4.1), 2 for cycle structure attack (section 4.2), 3 for asymmetric attack (section 4.3)
- n_bits_min - log(N), where N is the smallest domain on which to run
- n_bits_max - log(N), where N is the largest domain on which to run
- L_min - Smallest L on which to run (no lower than 3)
- L_max - Largest L on whicch to run (no greater than 5)
- mu - Number of attempts for PRF reconstruction
- t - Sets the number of bins used in attacks 4.1 and 4.2, and the number of ciphertext chains in attack 4.3
- t_flag - Additional parameter for attacks 4.1 and 4.3 - 0 to accept t as defined in the paper, 1 to set num bins or num chains to a constant value
- batch_id - ID of current test batch (used as a seed)
- k - Sample size of the experiment

To get the exact same results as described in the paper, run the following:

### Symmetric Attack (Section 4.1):

#### Constant 8 bins (table 2):

run_attack.sh 1 6 10 3 5 20 8.0 1 22 100

#### t=0.25 (table 3)

run_attack.sh 1 6 10 3 5 20 0.25 0 22 100

### Cycle Structure Attack (Section 4.2):

#### Constant 8 bins (table 4):

run_attack.sh 2 6 12 3 5 20 8.0 0 22 100

### Asymmetric Attack (Section 4.3):

#### Constant 3 chains (table 5):

run_attack.sh 3 6 11 3 5 20 3.0 1 22 100

#### t=0.5 (table 6):

run_attack.sh 3 6 11 3 5 20 0.5 0 22 100

## Processing Data

1. To gather all of the output files into a directory and generate a summary of the results, run:
    
    organize_test_results.sh \<attack_id\> \<n_bits_min\> <\n_bits_max\> <\L_min\> <\L_max\> <\mu\> <\t> <\t_flag\> <\batch_id\> <\k\>
    
    where the arguments passed are the exact same as in the previous step.

1. Then, to generate a LaTeX table of the results, run:
    
    python3 make_tex_file.py \<attack_id\> \<n_bits_min\> <\n_bits_max\> <\L_min\> <\L_max\> <\mu\> <\t> <\t_flag\> <\batch_id\> <\k\>
    
    redirected to the desired file.
