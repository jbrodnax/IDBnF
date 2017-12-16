#!/bin/bash
BIN=test_elf0
LFN=../load_funcs.py
CTR=../calltrace

python $LFN $BIN
$CTR $BIN ftable.txt
rm ftable.txt
