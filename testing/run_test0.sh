#!/bin/bash
BIN=test_elf0
LFN=../load_funcs.py
CTR=../main_v1

python $LFN $BIN
$CTR $BIN ftable.txt
rm ftable.txt
