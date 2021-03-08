#!/bin/bash

if [ $1 -eq 1 ]
then
	attack_name="symmetric_attack"
fi
if [ $1 -eq 2 ]
then
	attack_name="cycle_structure_attack"
fi
if [ $1 -eq 3 ]
then
	attack_name="asymmetric_attack"
fi

n_min=$2
n_max=$3
ell_min=$4
ell_max=$5
mu=$6
t=$7
t_flag=$8
batch_id=$9
k=${10}

for (( n=$n_min; n<=$n_max; n++ ))
do
	for (( ell=$ell_min; ell<=$ell_max; ell++ ))
	do
		dir_name=$attack_name-results.$n.$ell.$mu.$t.$t_flag.$batch_id
		mkdir $dir_name
		python3 process_results.py $1 $n $ell $mu $t $t_flag $batch_id $k > $dir_name/$dir_name.txt
		mv $attack_name.$n.$ell.$mu.$t.$t_flag.$batch_id.*.* $dir_name
	done
done
