# OverTheWire-Bandit #

[Website](http://overthewire.org/wargames/bandit/)

[OverTheWire Bandit](http://overthewire.org/wargames/bandit/) is a beginner-oriented wargame teaching / testing the basics of the Linux terminal, `ssh`, Unix/POSIX utilities, and some networking.

## Pre-requisites ##

All the levels of this wargame are accessed via `ssh`, the secure shell. If you are using any Linux or Mac OS X, you already have `ssh` (and many other terminal utilities) installed.

 - Linux - simply open a terminal, commonly hotkeyed to `Ctrl+Alt+T`.
 - Mac OS X - the Terminal.app application is *for our intents and purposes* equivalent to the Linux terminal, and you can find it in `/Applications/Utilities/Terminal.app`.
 - Windows - there are multiple options:
   - Use [PuTTY](http://www.putty.org/) - PuTTY is a freeware `ssh` client for Windows
   - Use a Virtual Machine - search for `linux vm on windows`
   - Use [Cygwin](https://www.cygwin.com/) - Cygwin provides Windows versions of many Linux utilities, including `ssh`.

## Notation used ##

In the level solutions below, we generally assume you are using `ssh` and a Linux / Mac OS X terminal. There will be blocks of code which you can / should execute in a terminal to clear the level. Once you connect to the Bandit server, you are connected to a Linux machine, so you can execute these commands remotely as well.

 - A dollar sign `$` represents user input to the terminal - a command which will run after you type it in and press enter.
 - A pound sign `#` represents other user action.
 - A greater-than sign `>` *describes* some terminal output.
 - Other lines will probably represent what the terminal outputs more literally. There may be some differences when you run commands yourself, or shortcuts to save space.

---

## Challenges ##

 - [Level 0](#level-0)
 - [Level 1](#level-1)
 - [Level 2](#level-2)
 - [Level 3](#level-3)
 - [Level 4](#level-4)
 - [Level 5](#level-5)
 - [Level 6](#level-6)
 - [Level 7](#level-7)
 - [Level 8](#level-8)
 - [Level 9](#level-9)
 - [Level 10](#level-10)
 - [Level 11](#level-11)
 - [Level 12](#level-12)
 - [Level 13](#level-13)
 - ...

---

## Level 0 ##

(Login: `bandit0:bandit0`)

To start this level, simply use your `ssh` client to connect to the given address on the given port. In PuTTY this is configured visually (and labeled clearly).

    $ ssh -p 2220 bandit0@bandit.labs.overthewire.org
    # input the password bandit0 (it will look like you are not typing, but you are)
    > a long string of text will inform you that you are connected to Bandit

To get to the next level, look around the directory you are in and read the file left there. `ls` lists the files in your current directory. `cat` prints out files to the terminal.

    $ ls
    readme
    $ cat readme
    boJ9jbbUNNfktd78OOpsqOltutMc3MY1

And there is the password for the next level. To disconnect and terminate our `ssh` session, press `Ctrl+D`.

## Level 1 ##

(Login: `bandit1:boJ9jbbUNNfktd78OOpsqOltutMc3MY1`)

In this level, there is an awkwardly-named file `-` in the directory.

    $ ls
    -

`cat -` does not work, because `-` means something special to `cat` (it makes it read from the terminal input). There are multiple ways to solve this problem. Firstly, you can represent the filepath differently.

There are some special paths in Linux systems:

 - `/` is *root* - the filesystem is represented as a tree structure, and it always has (just one) root. Even if there are multiple hard drives installed, they will be mounted on virtual directories that are part of the tree structure.
 - `.` represents the *current directory*. It is often useful when you want to provide the directory you are in as an argument to programs.
 - `..` represents the *parent directory*. `cd ..` takes you to up one level in the filesystem.
 - `~` represents the *user home directory*. User homes are directories which belong to a given user, and their owners (generally) have all permissions in them.

Knowing this, we can represent the file `-` in the current directory as `./-`, which no longer has a special meaning to `cat`:

    $ cat ./-
    CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9

There is one more way, by using *pipes*. Any Linux program / process has a number of open *file descriptors* by default. These are essentially virtual files, which the program can read from or write to:

 - `0` / `stdin` - the standard input.
 - `1` / `stdout` - the standard output.
 - `2` / `stderr` - the standard error output.

When you run a program in the terminal, what you write gets sent to the program's `stdin`, and the program's `stdout` and `stderr` are printed out in the terminal.

There are ways to redirect these file descriptors and they provide an extremely powerful way to combine the functionality of various programs.

 - `|` (pipe) between two commands redirects the `stdout` of one program to the `stdin` of another.
 - `&gt;` (file output) redirects the `stdout` of a program to a file. Important: the file is completely overwritten with the output.
 - `&gt;&gt;` (file append) redirects the `stdout` of a program to a file. This version keeps the original file contents intact, and appends the data to the end.
 - `&lt;` (file input) redirects a file to the `stdin` of a program.

`cat` with no arguments simply reads data from its `stdin` and outputs it back to its `stdout`. So:

    $ cat < -

We give `cat` the file on its `stdin`, and it copies it to its `stdout`, which is printed to our terminal.

## Level 2 ##

(Login: `bandit2:CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9`)

We have to read another file:

    $ ls
    spaces in this filename

Trying `cat spaces in this filename` directly fails. This is because command-line arguments in the terminal are separated using spaces, so to `cat`, it looks like we are asking it to read the file called "spaces", then the file called "in", etc. There is a way to specify arguments with spaces in them - we simply need to quote them properly:

    $ cat "spaces in this filename"
    UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
    $ cat 'spaces in this filename'
    UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK

There is another way, "escaping". Space has special meaning to the terminal, and sometimes we need to use special characters literally (i.e. we want a space to represent a space, not an argument separator). A very common convention is to escape characters using a backslash:

    $ cat spaces\ in\ this\ filename
    UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK

(If we wanted a literal backslash, that would be `\\`.)

A very effective way to make your terminal usage faster in general is to learn to use shortcuts. One of these is `TAB` which in any modern shell (terminal) does "tab completion". Whenever you are typing, pressing `TAB` will ask the shell to try to finish what you are typing, with a file or program:

    $ cat sp
    # now we press TAB and suddenly the terminal shows:
    $ cat spaces\ in\ this\ filename

It does all the work for us.

## Level 3 ##

(Login: `bandit3:UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK`)

We are told there is a hidden file we need to read.

    $ ls
    inhere
    $ cd inhere
    $ ls

But `ls` shows nothing at all. To find out what a hidden file is, we could search online, or we could see if we can change how `ls` works. Any standard Linux program has a "man page" (manual page). It is accessed using the program `man`.

    $ man ls
    > the manual opens up
    > press q to quit it, press h for more help, and use the arrows and space for basic navigation

In the manual, we can find that `ls` takes a special argument (flag), `-a` to "not ignore entries starting with .". As it turns out, files whose name starts with `.` are the Linux convention for hidden files. There is nothing special about them, except that they are usually hidden from users. Note that the special directories `.` and `..` also start with a `.` - and they are hidden in `ls` output, even though they are virtually part of every directory.

    $ ls -a
    .  ..  .hidden
    $ cat .hidden
    pIwrPrtPN36QITSp3EQaw936yaFoFgAB

## Level 4 ##

(Login: `bandit4:pIwrPrtPN36QITSp3EQaw936yaFoFgAB`)

    $ ls
    inhere
    $ cd inhere
    $ ls
    -file00  -file01  -file02  -file03  -file04  -file05  -file06  -file07  -file08  -file09

We have a bunch of files, most of which contain binary junk (which can mess up our terminal). We can use the program `file` to identify what each file is. It is useful to identify various forms of data, and it can often provide a reasonable guess. Once again, and argument starting with `-` would be interpreted as a special "flag" argument though. Just like in the previous levels, we could prepend `./` to each file and eventually we would find the correct one:

    $ file ./-file00
    ./-file00: data

But there is a faster way, using wildcards. These are special character that the shell interprets as "fill in the blanks" and expands them to several arguments. For instance:

    $ file ./*
    ./-file00: data
    ./-file01: data
    ./-file02: data
    ./-file03: data
    ./-file04: data
    ./-file05: data
    ./-file06: data
    ./-file07: ASCII text
    ./-file08: data
    ./-file09: data

We typed `./*`, meaning "all files in `.`, the current directory". `*` would mean the same thing, but we need to prefix the filenames with `./` to not confuse `file`. Note that this wildcard is interpreted by the <i>shell</i> before the program `file` is even run. It "preprocesses" the line before it executes it, so `./*` is literally replaced with `./-file00 ./-file01 ./-file02 ... ./-file09`, with the spaces included. `file` has no idea of what a wildcard is. Keep this in mind.

    $ cat ./-file07
    koReBOKuIDDepwhWk7jZC0RTdopnAYKh

## Level 5 ##

(Login: `bandit5:koReBOKuIDDepwhWk7jZC0RTdopnAYKh`)

    $ ls
    inhere
    $ cd inhere
    $ ls
    maybehere00  maybehere02  maybehere04  maybehere06  maybehere08  maybehere10  maybehere12  maybehere14  maybehere16  maybehere18
    maybehere01  maybehere03  maybehere05  maybehere07  maybehere09  maybehere11  maybehere13  maybehere15  maybehere17  maybehere19

There are a lot of files and we'd like one which is human-readable, 1033 bytes in size, and not executable. Fortunately, there is the command `find`, which allows us to specify various criteria and it will search for conforming files recursively. `man find` gives us some of what we need. As it turns out, specifying the size only (suffixed with `c` to indicate characters or bytes) is enough:

    $ find . -size 1033c
    ./maybehere07/.file2

We get one result, which is the correct one. But, if we want to specify the other criteria as well:

    $ find . ! -executable -size 1033c | xargs file
    ./maybehere07/.file2: ASCII text, with very long lines

`.` is the directory we are searching. `! -executable` means "not executable". `-size 1033c` is the size specification.

The rest is slightly more confusing. We pipe the `stdout` of `find`, which contains lines with one file path on each line. We want to see which files of those are human-readable, which is something `file` can do. Unfortunately, `file` takes arguments, and nothing in `stdin` - `find . | file` does not work because `file` needs an argument. Luckily, there is a command for that. It is `xargs`, and by default it takes lines (or words) from its `stdin` and gives them as arguments to the utility specified in <i>its</i> argument.

    $ cat ./maybehere07/.file2
    DXjZPULLxYr17uwoI01bNLQbtFemEgo7
    > (and there is a lot of spaces to make the file 1033 bytes in length)

## Level 6 ##

(Login: `bandit6:DXjZPULLxYr17uwoI01bNLQbtFemEgo7`)

Another `find` challenge. Consulting `man find` we can use:

    $ find / -user bandit7 -group bandit6 -size 33c
    > a lot of errors

`find` prints a lot of errors, because we (logged in as the user `bandit6`) do not have the permissions to read or see all the files on the system. The result is hidden among the results, but suppose we wanted to see the output of `find` without all of these errors. As is normal, these errors are actually printed to `stderr`, the error output of `find`. This differentiates errors from data. Basic piping, e.g. using `|` redirects `stdout` to other programs - it could cause problems if we passed lines with errors to other programs which don't know what to do with them. This is why Linux has two different outputs for each process.

There is more redirection syntax we have not used yet:

 - `1>file` redirects `stdout` to `file`.
 - `2>file` redirects `stderr` to `file`.

Recall that the standard file descriptors have numbers, 0-2. In fact, `stdin`, `stdout`, and `stderr` are open by default (hence "standard") by the terminal, but there is nothing really special about them - sometimes you can open additional file descriptors for processes, and they would simply be numbered 3 and higher.

There is no way to "close" or "ignore" an output. We could redirect `stderr` to a temporary file and then remove it, but in Linux there is already a "file" for this - `/dev/null`. It is not really a file, but whatever you write to it is simply lost forever. This is more useful than it sounds in Linux!

    $ find / -user bandit7 -group bandit6 -size 33c 2>/dev/null
    /var/lib/dpkg/info/bandit7.password
    $ cat /var/lib/dpkg/info/bandit7.password
    HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs

## Level 7 ##

(Login: `bandit7:HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs`)

    $ ls
    data.txt
    $ cat data.txt
    > too much data

(Note: if you ever `cat` a file that seems to go on forever, you can use `Ctrl+C` to terminate the process. `Ctrl+C` works for any process running in the terminal.)

It is time to use another command - `grep`. According to `man grep`, it searches files for lines which match a pattern. It its simplest form we can just give it a word and it will give us lines which contain that word:

    $ grep millionth data.txt
    millionth   cvX2JJa4CFALtqS87jk27qwqGhBM9plV

## Level 8 ##

(Login: `bandit8:cvX2JJa4CFALtqS87jk27qwqGhBM9plV`)

    $ ls
    data.txt
    $ cat data.txt
    > too much data again

We can look at the file `data.txt` with `cat`, although it floods our terminal and it is not always practical. We can use the command `less` to get a less overwhelming look into the data:

    $ cat data.txt | less
    # navigate the file similarly to man, quit with q, help with h

There is a lot of similar lines. According to the challenge, there are actually duplicates in this file, but clearly they are not necessarily adjacent. We can sort the lines alphabetically using `sort`.

    $ cat data.txt | sort | less

This makes the duplicates obvious. Now we need to find lines which are unique. `man uniq` to find:

    $ cat data.txt | sort | uniq -u
    UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR

Note that `uniq` only looks for consecutive duplicates. Without sorting the lines first, it would not work.

## Level 9 ##

(Login: `bandit9:UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR`)

    $ ls
    data.txt
    $ cat data.txt
    > binary data, not pretty

There is a command to extract human-readable ASCII parts from a file, called `strings`.

    $ strings data.txt
    > still a lot of false positives

We have another criterion - the password is preceded by several "=" characters. `grep` also works on its `stdin`:

    $ strings data.txt | grep ===
    ========== theOkM
    ========== password
    ========== is
    )========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk

## Level 10 ##

(Login: `bandit10:truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk`)

    $ ls
    data.txt
    $ cat data.txt 
    VGhlIHBhc3N3b3JkIGlzIElGdWt3S0dzRlc4TU9xM0lSRnFyeEUxaHhUTkViVVBSCg==

The Wikipedia page is helpful, but even without knowing what Base64 really is, we can easily see (`man base64`) that there is a utility to decode it.

    $ base64 -d data.txt
    The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR

## Level 11 ##

(Login: `bandit11:IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR`)

    $ ls
    data.txt
    $ cat data.txt
    Gur cnffjbeq vf 5Gr8L4qetPEsPk8htqjhRK8XSP6x2RHh

Once again, we can read up about rot-13 and Caesar ciphers on Wikipedia. There is a website dedicated to [rot-13](http://rot13.org/), as well as a more Linux-y way of doing this, using the `tr` utility:

    $ cat data.txt | tr a-zA-Z n-za-mN-ZA-M
    The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu

To `tr`, the above is the same as:

    $ cat data.txt | tr abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM
    The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu

But we can collapse ranges of consecutive characters. Simply put, whenever `tr` finds a character that is specified in its first argument, it replaces it with the character in the same position in its second argument. Rot-13 replaces each letter of the alphabet with the letter 13 positions down. The above command makes this quite explicit (i.e. an `a` in the first string corresponds to an `n` in the second).

## Level 12 ##

(Login: `bandit12:5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu`)

    $ ls
    data.txt
    $ cat data.txt
    > a hexdump

The recommended way to do this (according to the challenge) is to create temporary files in `/tmp` and work step by step. The following is a method with no temporary files needed, using only pipes.

During this level, we will encounter various data types. Most of these can be identified using `file`. `file` also works on its `stdin`, if it is given `-` as an argument. So the following two are equivalent:

    $ file data.txt 
    data.txt: ASCII text
    $ cat data.txt | file -
    /dev/stdin: ASCII text

Using `file -`, we can always tell what is coming out of our pipe:

	<li>`xxd` hexdump (ASCII text, identifiable by manual examination)</li>
	<li>`gzip` compressed data</li>
	<li>`bzip2` compressed data</li>
	<li>`tar` archive</li>

For each of these, we have a decoder command, and a way to process it in pipes. The only slightly more complicated one is `tar`:

	<li>`xxd -r` reverses its hexdump</li>
	<li>`gunzip -` unzips `gzip`</li>
	<li>`bunzip2 -` unzips `bzip2`</li>
	<li>`tar xfO - &lt;filename&gt;` extracts &lt;filename&gt; from a `tar` archive</li>

Getting started:

    $ cat data.txt | file -
    /dev/stdin: ASCII text
    $ cat data.txt | xxd -r | file -
    /dev/stdin: gzip compressed data, was "data2.bin", last modified: Mon Nov 13 14:58:07 2017, max compression, from Unix
    $ cat data.txt | xxd -r | gunzip - | file -
    /dev/stdin: bzip2 compressed data, block size = 900k
    $ cat data.txt | xxd -r | gunzip - | bunzip2 - | file -
    /dev/stdin: gzip compressed data, was "data4.bin", last modified: Mon Nov 13 14:58:07 2017, max compression, from Unix
    $ cat data.txt | xxd -r | gunzip - | bunzip2 - | gunzip - | file -
    /dev/stdin: POSIX tar archive (GNU)

The problem with the `tar` format is that it is a multi-file format. In our case, the `tar` archives always contain a single file, but we need to know its name before we can extract it via the pipe stream. We can do this using `tar t`:

    $ cat data.txt | xxd -r | gunzip - | bunzip2 - | gunzip - | tar t
    data5.bin
    $ cat data.txt | xxd -r | gunzip - | bunzip2 - | gunzip - | tar Oxf - data5.bin | file -
    /dev/stdin: POSIX tar archive (GNU)
    $ cat data.txt | xxd -r | gunzip - | bunzip2 - | gunzip - | tar Oxf - data5.bin | tar t
    data6.bin
    $ cat data.txt | xxd -r | gunzip - | bunzip2 - | gunzip - | tar Oxf - data5.bin | tar Oxf - data6.bin | file -
    /dev/stdin: bzip2 compressed data, block size = 900k
    $ cat data.txt | xxd -r | gunzip - | bunzip2 - | gunzip - | tar Oxf - data5.bin | tar Oxf - data6.bin | bunzip2 - | file -
    /dev/stdin: POSIX tar archive (GNU)
    $ cat data.txt | xxd -r | gunzip - | bunzip2 - | gunzip - | tar Oxf - data5.bin | tar Oxf - data6.bin | bunzip2 - | tar t
    data8.bin
    $ cat data.txt | xxd -r | gunzip - | bunzip2 - | gunzip - | tar Oxf - data5.bin | tar Oxf - data6.bin | bunzip2 - | tar Oxf - data8.bin | file -
    /dev/stdin: gzip compressed data, was "data9.bin", last modified: Mon Nov 13 14:58:07 2017, max compression, from Unix
    $ cat data.txt | xxd -r | gunzip - | bunzip2 - | gunzip - | tar Oxf - data5.bin | tar Oxf - data6.bin | bunzip2 - | tar Oxf - data8.bin | gunzip -
    The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL

## Level 13 ##

(Login: `bandit13:8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL`)

(TODO!)
