#!/bin/bash

(
# add 1000 credentials
for i in {1..1000}; do
    printf "1\nro\not1\n"
    sleep 0.05
done

# login as root
printf "2\nroot\n1\n"
sleep 0.5
) | nc secure-hash.ctf.hackover.de 1337
