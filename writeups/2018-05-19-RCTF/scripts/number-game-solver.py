#!/usr/bin/env python3

import collections
from hashlib import sha256
import itertools
import socket
import sys

def pow_hash(suffix, candidate):
    plain = "{}{}".format(candidate, suffix)
    return sha256(bytes(plain, "ascii")).hexdigest()

def solve_pow(suffix, target):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for candidate in map("".join, itertools.product(*[ alphabet for i in range(4) ])):
        if pow_hash(suffix, candidate) == target:
            return candidate
    return None

# mastermind solver from:
#  https://github.com/Michael0x2a/mastermind-solver/blob/master/python/solve_mastermind.py

Feedback = collections.namedtuple('Feedback', ['correct', 'close'])

def generate_initial_pool(choices, holes):
    ret = list(itertools.product(*[range(choices) for _ in range(holes)]))
    return [ g for g in ret if len(g) == len(set(g)) ]

def find_correct(actual, guess):
    return sum([1 for (a, b) in zip(actual, guess) if a == b])

def remove_correct(actual, guess):
    actual2 = [a for (a, b) in zip(actual, guess) if a != b]
    guess2 = [b for (a, b) in zip(actual, guess) if a != b]
    return actual2, guess2

def find_close(actual, guess):
    actual, guess = remove_correct(actual, guess)
    close = 0
    for possible in guess:
        if possible in actual:
            del actual[actual.index(possible)]
            close += 1
    return close

def get_feedback(actual, guess):
    return Feedback(find_correct(actual, guess), find_close(actual, guess))

def is_match(guess, feedback, possible):
    return feedback == get_feedback(possible, guess)

def filter_pool(pool, guess, feedback):
    for possible in pool:
        if is_match(guess, feedback, possible) and (possible != guess):
            yield possible

def make_guess(pool, feedback):
    min_length = float('infinity')
    best_choice = None
    for possible in pool:
        length = len(list(filter_pool(pool, possible, feedback)))
        if min_length > length:
            min_length = length
            best_choice = possible
    return best_choice


def play(choices, holes, attempt):
    pool = generate_initial_pool(choices, holes)
    guess = [0, 1, 2, 3]
    wasFirst = True
    while True:
        correct, close = attempt(guess)
        feedback = Feedback(correct, close)
        if feedback.correct == holes:
            break
        pool = list(filter_pool(pool, guess, feedback))
        if wasFirst and feedback.correct == 0 and feedback.close == 2:
            guess = (1, 4, 3, 5)
        elif wasFirst and feedback.correct == 0 and feedback.close == 1:
            guess = (1, 4, 5, 6)
        elif wasFirst and feedback.correct == 2 and feedback.close == 0:
            guess = (0, 1, 4, 5)
        elif wasFirst and feedback.correct == 0 and feedback.close == 0:
            guess = (4, 5, 6, 7)
        else:
            guess = make_guess(pool, feedback)
        wasFirst = False

buf = b""
curAttempts = 0
correct = 0

if __name__ == '__main__':
    while True:
        buf = b""
        print("connecting ...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("149.28.139.172", 10002))
        def recvUntil(msg):
            global buf
            while True:
                try:
                    found = buf.find(bytes(msg, "utf8"))
                    if found != -1:
                        ret, buf = buf[0:found].decode("utf8"), buf[found + len(msg):]
                        return ret
                    recvd = sock.recv(4096)
                    if len(recvd) > 0:
                        print("> {}".format(str(recvd)))
                        buf += recvd
                except BlockingIOError:
                    pass
                except ConnectionResetError:
                    return buf.decode("utf8")
        def send(msg):
            sock.sendall(bytes(msg, "utf8"))
        buf = b""
        recvUntil("sha256(****+")
        suffix = recvUntil(") == ")
        target = recvUntil("\nGive me XXXX:")
        print("solving {} {}".format(suffix, target))
        solution = solve_pow(suffix, target)
        print("got {}".format(solution))
        send("{}\n".format(solution))
        recvUntil("GLHF\n")
        recvUntil("\n")
        playing = True
        correct = 0
        while playing:
            recvUntil("Give me ")
            holes = int(recvUntil(" numbers, in["))
            numMin = int(recvUntil(", "))
            numMax = int(recvUntil("), You can only try "))
            maxAttempts = int(recvUntil(" times\n"))
            curAttempts = 0
            print("holes: {}, min: {}, max: {}, attempts: {}".format(holes, numMin, numMax, maxAttempts))
            def attempt(guess):
                global curAttempts
                global playing
                global correct
                send("{}\n".format(" ".join(map(str, guess))))
                resp = recvUntil("\n")
                curAttempts += 1
                if resp[0:5] == "Nope.":
                    if curAttempts >= maxAttempts:
                        print("({})".format(buf.decode("utf8")))
                        playing = False
                        return (holes, 0)
                    resp = list(map(int, resp[6:].split(", ")))
                    print("{} -> {}".format(str(guess), str(resp)))
                    return (resp[0], resp[1])
                elif resp[0:10] == "You lose, ":
                    playing = False
                    return (holes, 0)
                else:
                    print("correct: {}".format(str(guess)))
                    correct += 1
                    if correct >= 8:
                        while True:
                            print(recvUntil("\n"))
            play(numMax - numMin, holes, attempt)
        sock.close()

# RCTF{0lD_GaM3_nAmed_Bu11s_4nd_C0ws}
