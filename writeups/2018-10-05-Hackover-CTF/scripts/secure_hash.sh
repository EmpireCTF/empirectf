#!/bin/bash

(
# add fake credentials
printf "1\nro\not1\n"
sleep 0.5

# login as root
printf "2\nroot\n1\n"
sleep 0.5
) | nc secure-hash.ctf.hackover.de 1337
