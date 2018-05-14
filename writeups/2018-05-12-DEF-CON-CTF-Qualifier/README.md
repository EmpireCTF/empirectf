# 2018-05-05-PlaidCTF #

[CTFTime link](https://ctftime.org/event/608) | [Website](https://scoreboard.oooverflow.io/)

---

## Challenges ##

 > Note: incomplete challenge listing

### Amuse Bouche ###

 - [x] [102 ELF Crumble](#102-elf-crumble)
 - [x] [101 You Already Know](#101-you-already-know)
 - [x] [104 Easy Pisy](#104-easy-pisy)

### Guest Chefs ###

 - [x] [104 PHP Eval White-List](#104-php-eval-white-list)
 - [x] [121 ghettohackers: Throwback](#121-ghettohackers-throwback)

---

## 102 ELF Crumble ##

(warmup)

**Files provided**

 - `broken`
 - `fragment_1.dat`
 - `fragment_2.dat`
 - `fragment_3.dat`
 - `fragment_4.dat`
 - `fragment_5.dat`
 - `fragment_6.dat`
 - `fragment_7.dat`
 - `fragment_8.dat`

**Description**

We were given an executable, `broken`, which has a big hole in the middle, filled with X's. The size of the hole is the same as all the fragment sizes added up, so it was quite clear we were meant to assemble the fragments into the binary in the correct order.

**Solution**

Certainly inspecting the fragments would be helpful, checking alignment and instructions. But, since the CTF started at 1am for me and I wanted to sleep before starting for real, the lazy (but computer-time-intensive) solution is to just assemble the binary in every possible way, then run them all. Script:

    #!/bin/bash
    
    # `broken` parts before and after the hole
    dd bs=1 count=1453 if=broken of=broken_pre
    dd bs=1 skip=2260 if=broken of=broken_post
    echo "prefix and postfix created ..."
    
    # permutation function, from https://stackoverflow.com/a/3846321
    function perm() {
        local fragments="$1"
        local order="$2"
        local i
        [[ "$fragments" == "" ]] && echo "$order" && return
        for (( i=0; i<${#fragments}; i++ )); do
            perm "${fragments:0:i}${fragments:i+1}" "$order${fragments:i:1}"
        done
    }
    
    # assemble all permutations into binaries
    mkdir -p perm
    fragments="12345678"
    perm "$fragments" | while read order; do
        ((count++))
        echo "$count: $order"
        (
            cat broken_pre
            for (( i=0; i<${#order}; i++ )); do
                cat "fragment_${order:i:1}.dat"
            done
            cat broken_post
        ) > "perm/$order"
        chmod +x "perm/$order"
    done
    echo "binaries generated ..."
    
    # run all binaries in parallel, record output in out
    mkdir -p out
    for f in perm/*; do
        ( ("$f" 2>&1 >"out/"`basename $f`".txt") &)
    done
    echo "binaries executed ..."
    
    # find unique outputs
    printf "flag: "
    find out -type file -not -empty -exec cat {} \;

After some time, prints out `welcOOOme`.

## 101 You Already Know ##

(warmup)

**No files provided**

**Description**

> You already know the answer here.
> 
> **Seriously**, *if you can read this*, you already have the flag.
> 
> Submit it!

(More or less, I don't remember the exact wording.)

**Solution**

After trying to paste various pieces of the text into the flag submission box, and being annoyed (because PoW + timeouts), I finally thought about the challenge a bit more. The rules clearly said flags are always in the format `OOO{...}` unless stated otherwise in the description. So after having tried the literal `OOO{...}`, I checked the web inspector.

The HTML for the description box did not contain anything interesting. However, there was a delay between opening the description box and the text loading - clearly the data was loaded asynchronously via AJAX, which enabled the challenges to be revealed by the organisers whenever without having to reload the website.

So, recording the network activity, opening the challenge description triggers a request whose response contained `OOO{Sometimes, the answer is just staring you in the face. We have all been there}`. It was marked as a comment so the respone parser would not even put it into the HTML.

## 104 Easy Pisy ##

(crypto, web)

**Files provided**

 - `samples.tgz` - an archive containing
   - `echo-ciao.pdf` - a PDF with the text "ECHO ciao"
   - `echo-ciao.sign` - signature for `echo-ciao.pdf`
   - `execute-ls.pdf` - a PDF with the text "EXECUTE ls"
   - `execute-ls.sign` - signature for `execute-ls.pdf`

**Description**

The target website contained two forms - one to upload a PDF file and have the server sign it, and another one to upload a PDF file with a signature and have the server execute it.

**Solution**

After some testing and viewing the PHP file sources (via public debug parameter), it was clear that the server is using ImageMagick to `convert` the PDF file into a PPM bitmap, then using `ocram` to read the text visually. The signing was done via `openssl_sign` and `openssl_verify`, using the default SHA algorithm, but then encrypting the signature using RSA. Uploading the given `EXECUTE ls` file with its proper signature revealed that the public and private key are in the same directory, but the access was forbidden. There was also a `flag` file, likewise inaccessible.

I spent way too long trying to figure out something clever for this one. I knew about the SHAttered attack but for some reason I thought it still takes a long time to actually construct two matching files. So, in my fumbling around I learnt a bunch about how PDFs work, and was trying / considering these attack vectors:

 - length extension attack - impossible since the signature is encrypted
 - make the PDF file include `flag` via filespec - PDF embedded files can't actually be displayed as content (AFAIK)
 - `openssl_verify` wasn't checked properly, trip it up by sending malformed signature? - no luck
 - OCR exploit - ???

So, in the end … Simply use [sha1collider](https://github.com/nneonneo/sha1collider). Make a PDF that just shows "EXECUTE cat flag", then `python3 collide.py execute-ls.pdf execute-catflag.pdf` and done. At least I learnt something! `OOO{phP_4lw4y5_d3l1v3r5_3h7_b35T_fl4g5}`

## 104 PHP Eval White-List ##

(re, web)

**Files provided**

 - `eval.so`

**Description**

The challenge website which lets us run PHP's `eval` with "patched" version of `eval`. The shared object file contained the patched function.

**Solution**

Since the website said to try and execute `flag`, before even looking into the shared object, I tried `system("../flag")`. Done: `OOO{Fortunately_php_has_some_rock_solid_defense_in_depth_mecanisms,_so-everything_is_fine.}`

## 121 ghettohackers: Throwback ##

(misc)

**Files provided**

 - `text`

**Description**

The `text` file contained:

> Anyo!e!howouldsacrificepo!icyforexecu!!onspeedthink!securityisacomm!ditytop!urintoasy!tem!

**Solution**

Naturally my first instinct was to fill in the missing letters. So, filling in the blanks, we get:

> Anyone who would sacrifice policy for execution speed thinks security is a commodity to pour in to a system!

The letters we filled in were `nwltisoos`. This doesn't really look like anything and it was not the flag. The description and the title of the challenge hinted at DEF CON CTFs from a long time ago. I assume this sort of challenge was indeed part of an old CTF, but I couldn't find it. Searching for the quote itself was not successful either, there was no exact match for this sentence.

In my text editor the text was laid out like this:

    Anyo!e!howouldsacrificepo!icyforexecu!!onspeedthink!securityisacomm!ditytop!urintoasy!tem!
        n w                  l           ti            s               o       o         s   .

So I focused on the blanks between the filled-in letters. Counting the number of spaces between each blank (and the beginning):

    4-1-18-11-0-12-15-7-9-3

And, substituting 1 for A, 2 for B, etc, and 0 for a space, that gives us the flag, `dark logic`.
