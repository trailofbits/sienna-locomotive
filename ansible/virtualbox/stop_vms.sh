#!/bin/bash

template="$1"
run_uid="$2"
number_worker="$3"


for i in $(seq 0 $(($number_worker -1))); do
    stop_vm=$template"_"$i
    vboxmanage controlvm $stop_vm poweroff; 
done
