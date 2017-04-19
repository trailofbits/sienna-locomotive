#!/bin/bash

template="$1"
run_uid="$2"
number_worker="$3"


for i in $(seq 0 $(($number_worker -1))); do
    new_vm=$template"_"$i
    vboxmanage startvm $new_vm;
done
#vboxmanage modifyvm vm-name | vm-uuid --macaddress1 auto 
