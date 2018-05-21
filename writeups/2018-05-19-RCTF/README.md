# 2018-05-19-RCTF #

[CTFTime link](https://ctftime.org/event/624) | [Website](https://rctf2018.xctf.org.cn/)

---

## Challenges ##

### Misc ###

 - [x] [206 Number Game](#206-misc--number-game)
 - [x] [52 git](#52-misc--git)
 - [ ] 606 520 gift
 - [x] [256 cats](#256-misc--cats)
 - [x] [377 cats Rev.2](#377-misc--cats-rev2)
 - [x] [73 sign](#73-misc--sign)

### Crypto ###

 - [ ] [416 ECDH](#416-crypto--ecdh)
 - [x] [176 cpushop](#176-crypto--cpushop)

### Reverse ###

 - [x] [540 magic](#530-reverse--magic)
 - [x] [161 babyre](#161-reverse--babyre)
 - [ ] [588 compiler](#588-reverse--compiler)
 - [x] [317 simple vm](#317-reverse--simple-vm)
 - [x] [606 simple re](#606-reverse--simple-re)
 - [x] [338 sql](#338-reverse--sql)
 - [x] [444 babyre2](#444-reverse--babyre2)

### Web ###

 - [ ] [769](#769-web--no-js)
 - [ ] [606](#606-web--backdoor)
 - [ ] [487](#487-web--amp)
 - [ ] [869](#869-web--retter)
 - [x] [500](#500-web--r-cursive)
 - [ ] [769](#769-web--rblog-2018-rev2)
 - [ ] [434](#434-web--rblog-2018)

### Pwn ###

 - [ ] [317](#317-pwn--babyheap)
 - [ ] [540](#540-pwn--stringer)
 - [ ] [465](#465-pwn--rnote4)
 - [ ] [384](#384-pwn--rnote3)
 - [ ] [454](#454-pwn--simulator)

---

## 206 Misc / Number Game ##

**Description**

> Guess Guess Guess
> 
> nc 149.28.139.172 10002

**Solution**

Upon connecting, we get a standard PoW prompt:

    sha256(****+UJBS55MXKhMOcSQO) == 4e3cefcf649092ef546aaabfcfa628e63377ce08bf17012f628ac48fbba2307d
    Give me XXXX:

([simple PoW solver](scripts/pow.py))

After solving the PoW:

      o__ __o             o__ __o    ____o__ __o____   o__ __o__/_ 
     <|     v\           /v     v\    /   \   /   \   <|    v      
     / \     <\         />       <\        \o/        < >          
     \o/     o/       o/                    |          |           
      |__  _<|       <|                    < >         o__/_       
      |       \       \                    |          |           
     <o>       \o       \         /         o         <o>          
      |         v\       o       o         <|          |           
     / \         <\      <\__ __/>         / \        / \          
                                                                   
                                                                   
                                                                   
    In every round of the game, I'll choose some different numbers from the figure interval. You are required to guess those numbers,ofc so does the order of them.
    On each surmise of yours, 2 numbers will be told as a hint for you, but you need to speculate the fuctions of these 2 figures. (XD
    GLHF
                                                                   
    ================== round 1 ================== 
    Give me 4 numbers, in[0, 10), You can only try 6 times

Some string format vulns and overflows were tried, but no luck, we actually have to solve the game properly. Providing 4 numbers returns e.g.:

    Nope. 1, 0

Should be familiar, it's the [Mastermind game](https://en.wikipedia.org/wiki/Mastermind_(board_game)), apparently also known as "cows and bulls". In each round, there is a hidden sequence of four numbers, 0 through 9. We get 6 attempts to guess the correct sequence. With each incorrect attempt, we get two pieces of feedback:

 - "blacks" - how many of our numbers are in the hidden sequence AND in the same position
 - "whites" - how many of our numbers are in the hidden sequence but NOT in the same position

So I ~~stole~~ adapted a Mastermind solver from [here](https://github.com/Michael0x2a/mastermind-solver/blob/master/python/solve_mastermind.py) (thanks @Michael0x2a!). The principle is simple:

 1. generate a pool of all possible guesses, for 10 different numbers and a sequence of 4 numbers, there are 10000 possible sequences
 2. pick a guess and get feedback for it
 3. if incorrect, eliminate all guesses from the pool that are inconsistent with the feedback and go back to step 2

The first guess is always `[0, 0, 1, 1]` for the 10 number 4-sequence (as it turns out all rounds are actually like this). There is an additional heuristic in picking a good guess, namely, a guess which may reduce the pool to the fewest remaining sequences.

I added socket interaction and the PoW solver to make it automated. After letting it run for a bit, I was disappointed to see that it rarely got past 4 rounds, and at this point I found out on the IRC that there are 8 rounds before you get the flag.

Mostly hopeless, I looked at the correct solutions it got to the few rounds it managed. Interestingly enough, among all the correct solutions, there was never a sequence with duplicate numbers! So, I removed these sequences from the initial pool and made the initial guess to always be `[0, 1, 2, 3]`.

With this modification the results were immediately better and in just a couple of attempts the flag was obtained!

`RCTF{0lD_GaM3_nAmed_Bu11s_4nd_C0ws}`

([full script here](scripts/number-game-solver.py))

## 52 Misc / git ##

**Description**

> My file lost! 
> 
> attachment: https://drive.google.com/open?id=1Mo3uN2FV1J-lbqjQZvvXitWagZqjD1Xi 

**Solution**

The attachment is a zip archive with this directory structure:

    git/
        .git/
            ...
        HelloWorld.txt

There is no stash nor commits in the log, and the `develop` branch seems to be the same. But, using `git reflog`:

    22d3349 HEAD@{0}: checkout: moving from develop to master
    22d3349 HEAD@{1}: rebase -i (finish): returning to refs/heads/develop
    22d3349 HEAD@{2}: rebase -i (start): checkout 22d3349
    f671986 HEAD@{3}: checkout: moving from master to develop
    22d3349 HEAD@{4}: checkout: moving from develop to master
    f671986 HEAD@{5}: checkout: moving from master to develop
    22d3349 HEAD@{6}: checkout: moving from rctf to master
    f671986 HEAD@{7}: commit: Revert
    f4d0f6d HEAD@{8}: commit: Flag
    22d3349 HEAD@{9}: checkout: moving from master to rctf
    22d3349 HEAD@{10}: commit (initial): Initial Commit

We see there was a `Flag` commit that was reverted. So we can `git checkout f4d0f6d` which reveals the `flag.txt` file.

`RCTF{gIt_BranCh_aNd_l0g}`

## 256 Misc / cats ##

**Description**

> I love cats! PS: This is NOT a web challenge. Just find the cats.
> 
> http://cats.2018.teamrois.cn:1337

**Solution**

At the address we see:

![](screens/cats.png)

And the linked dockerfile:

    FROM ubuntu:latest
    ENV TZ=Asia/Shanghai
    RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
    RUN apt-get update && apt-get install -y php python3 nodejs ruby && mkdir /app
    WORKDIR /app
    
    # build: docker build -t rctf_cats .
    # judge: docker run -it --rm --network none -v /tmp/yourCatFood:/app/food:ro rctf_cats bash -c "timeout 5 diff -Z <(cat food) <(eachCatNameYouProvided food)"

So, without bothering to actually set up Docker, we see that it runs the command `timeout 5 diff -Z <(cat food) <(eachCatNameYouProvided food)`. Whatever we put into the textarea will be the contents of the file `food`. Then the command compares the output of `cat food`, i.e. the contents we provided, with 15 commands we provide in the second input invoked with the argument `food`.

Some other details – `cat` doesn't count as a cat (too obvious I guess!), and thanks to the regex we cannot provide any commandline arguments, just the names of commands that we want to run. Finally, the content of the file has to be at least 2 bytes, but no more than 1337 bytes, so an empty file is unfortunately not possible.

The solution was obtained by using a basic Ubuntu VM. In the shell I typed `a`, then presed tab twice to get a listing of commands that start with `a`, then looked for anything that might work. Same for every other letter.

The most important thing to realise for this part of the challenge was probably that we need to have 15 commands that will output the same thing as `cat food` *in this particular* setup. We don't actually need to find 15 commands that do the same thing as `cat` (why would they even exist then?).

So, the commands I provided fall into two categories:

 - ones which treat the argument `food` as a path or filename (e.g. `ls`)
 - ones which treat the argument `food` as a string (e.g. `echo`)

Thinking of `echo food` and `cat food`, I decided the best choice for the contents of the `food` file was the literal string `food`. Then `cat food` simply outputs `food`. Useful.

And so finally, the list of commands I chose:

 - `ls` - normally lists directories, but given a path to a file it simply outputs its name (this is more useful when combined with other arguments)
 - `dir` - basically the same as `ls` as far as I can tell
 - `more` - normally provides an interactive terminal viewer for file contents, but when piped into a command like `diff` it behaves just like `cat`
 - `php` - by default, PHP copies file contents to stdout, unless it finds the tag `<?php` (or `<?`)
 - `uniq` - filters out non-unique consecutive lines of a file; with a single line there is nothing to filter and it just prints it to output
 - `sort` - sorts the lines of a file; nothing to sort with a single line
 - `head` - shows the first N (10 by default) lines of a file
 - `tail` - shows the last N (10 by default) lines of a file
 - `find` - finds files by name, without a pattern just looks for a file called `food` and outputs its name
 - `echo` - prints out its argument to stdout
 - `fold` - prints out contents of a file, wrapping long lines
 - `expr` - evaluate expressions in arguments; `food` is just a string, so it is printed as-is
 - `paste` - print out files side-by-side, with a single file argument it is just `cat`
 - `fmt` - formats file contents according to arguments 
 - `basename` - given a path, print out only its last part

And with that:

> Wew, you've found 15 cats! Here is your flag: RCTF{you_love_cats_dont_you}. If you can find at least 4 out of 5 cats whose names in (python3, bash, php, node, ruby), I will give you another flag ._.

## 377 Misc / cats Rev.2 ##

**Description**

> solve cats first 
> 
> http://cats.2018.teamrois.cn:1337

**Solution**

Using the hint from the solution to `cats`, we need another list of 15 commands, but they must include at least 4 of `python3`, `bash`, `php`, `node`, `ruby`.

Script interpreters like these are generally happy to just do nothing when given an empty input file, but our `food` file must be at least 2 bytes in size! This immediately meant one thing: polyglot quine, or polyquine for short.

A "polyglot" in a programming context is a piece of code that is valid (and preferably does the same thing) in multiple languages. A lot of simple Python scripts are technically polyglots, since they work in both Python 2 and Python 3. The less similar the syntax of two languages is, the more difficult it is to make a polyglot with them, naturally.

And a "quine" in a programming context is a program which produces its own source code when executed. Generally, if this is accomplished by actually opening and reading the source file the program is considered a "cheating quine", since a lot of the difficulty of this problem is in crafting a string which somehow expands into the full program when formatted in a particular way. Fortunately, there is no restriction in this challenge, and a cheating quine is completely fine.

At first I looked online for similar challenges, and [this answer](https://codegolf.stackexchange.com/a/163371) seemed the closest to what I needed. Unfortunately, `perl` was not on the list of possible languages, and the challenge asked for Python 3, not Python 2. I spent some time trying to adapt this to work better, but I could only ever make it work for 3 languages at a time.

Then I decided to write my own polyquine, and solve the challenge the hard way. There was no particular method to my development, just writing some code and seeing which interpreter complains about the changes and why, then fixing it and so on. Of the 5 languages I chose `python3`, `bash`, `php`, and `node`, since I knew their syntax well enough. `ruby` not so much.

The script I came up with during the CTF was:

    a=0;food=1;exit=0;cat=2;echo=3;x=5;int=6
    cat <food
    echo
    exit <food
    int; 1//5 # <?php die(substr(file_get_contents("food"),79)."\n"); ?>
    int; 2//5 or __import__("sys").stdout.write(open("food").read() + "\n") and quit() and """
    x ;console.log(require("fs").readFileSync("food", "utf8"));
    x//"""

I made no effort to clean it up (mostly a waste of time if it works), but for this write-up I will describe a smaller version. The core functionality is the same.

    a=0;cat=0;echo=0;exit=0;food=0;i=0
    cat<food
    echo;exit
    i//1#<?die(substr(file_get_contents("food"),59)."\n");?>
    i//2;print(open("food").read());quit();"""
    x =0;console.log(require("fs").readFileSync("food","utf8"))
    x//"""

Some things could still be removed, but I kept them to make sure `sort` prints the file out as-is, i.e. the lines need to be sorted already. Let's see how each language interprets this code.

### PHP ###

PHP is the simplest to understand. By default, PHP just copies file contents to standard output. Any actual scripting capability is possible only in PHP mode, which is entered when a `<?php` tag is encountered, or the short version `<?`. So PHP first prints out everything from `a=0;cat= ...` all the way until `i//1#`. Then it executes this code:

    die(substr(file_get_contents("food"),59)."\n");

`file_get_contents("food")` returns the entire `food` file contents as a string. `substr(..., 59)` removes the first 59 characters (to account for the first part of the file that has already been printed). A `"\n"` newline is added for consistency with `cat` and the other interpreters. `die(...)` outputs the string to stdout and stops execution.

### Bash ###

`a=0` is a variable assignment in Bash. Multiple statements can be combined into one line by joining them with a `;` semicolon. `cat<food` redirects the file `food` into `cat`, which then outputs it. `echo` puts an extra newline and `exit` stops execution. After `exit`, the lines no longer have to make sense to Bash, since it interprets the file line by line.

### Javascript (NodeJS) ###

JS is unhappy about statements using variables that haven't been declared yet, e.g. `a + b` can throw an error if either `a` or `b` are not variables. Usually, variables are declared as `var a = "value";`, i.e. using the `var` keyword (or `let` or `const` in more modern JS). However, an assignment without the `var` keyboard is still valid, but it creates a global variable (in the global `window` object). So the first line is just creating a bunch of variables. Statements in JS can be terminated with a semicolon, but the semicolon can usually be omitted at the end of the line. This hurts my eyes but here it is convenient for a smaller file.

`cat<food` is a less-than comparison to JS. `echo` and `exit` use the previously declared variables, but the statements don't actually do anything. 

The `i//1...` and `i//2...` lines are also just using the `i` variable. Everything after `//` is ignored as a comment. Same for the last line `x//"""`.

So the most important statement is `console.log(require("fs").readFileSync("food","utf8"));`, which requires / imports the `fs` API from NodeJS standard libary, then calls its `readFileSync` function, which synchronously reads the file `food` and decodes it as a UTF-8 string. Finally, `console.log(...)` outputs this string to stdout (along with a trailing newline).

### Python 3 ###

The first three lines are interpreted similarly to JS. Some variables are declared and values are assigned to them, then some no-op expressions are evaluated.

But, `i//1` in Python means integer division of `i` by `1`. The rest of line 4 is ignored, because `#` starts a line comment.

`print(open("food").read())` does the actual source code output (and a trailing newline). `quit()` then stops execution. Finally `"""` starts a multiline string, which carries on till the end of the file, so the last two lines are not considered code and hence don't have to make sense to Python.

### 11 other cats ###

And with that, I fulfilled the requirement of using 4 out of the 5 specified languages. I considered adding `ruby`, but again, I don't know much about its syntax so I made due with what I had. The 11 other commands I used were:

 - `sh`, `dash`, `rbash` - other Bash-like shells which have some differences but interpret this script the same way
 - `head`, `tail`, `uniq`, `more`, `paste` - same as in `cats`
 - `zmore` - views compressed files directly on terminal, but also shows uncompressed files verbatim
 - `sort` - this is why I made sure the lines of code are sorted already
 - `python3m` - equivalent to `python3 --with-pymalloc` which does not affect Python's functionality.

And with that:

> Wew, you've found 15 cats! Here is your flag: RCTF{you_love_cats_dont_you}. You are so lihai! RCTF{did_you_make_a_polyglot}

I did indeed.
