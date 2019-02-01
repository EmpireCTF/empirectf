# OverTheWire-Natas #

[Website](http://overthewire.org/wargames/natas/)

[OverTheWire Natas](http://overthewire.org/wargames/natas/) is a beginner-oriented wargame teaching / testing the basics of web exploitation, PHP scripting, SQL injections, and more.

## Pre-requisites ##

All the levels of this wargame are accessed via web browser. Any browser has the functionality to display the page source and modify it if needed using the included web developer tools.

 - Google Chrome / Chromium
   - Developer tools - `F12` on Windows, `Cmd-Alt-I` on Mac OS X
 - Firefox
   - Developer tools - `F12`

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
 - [Level 14](#level-14)
 - ...

---

## Level 0 ##

(Login: `natas0:natas0`)

To start this level, simply navigate your browser to `http://natas0.natas.labs.overthewire.org/`. The username and password are both `natas0`.

The level is explicit about what to do. After opening the page source, we can find:

    <!--The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto -->

Note the convention - anything level-related will be inside the `<div id="content">` tag.

## Level 1 ##

(Login: `natas1:gtVrDuiDfck831PqWsLEZy5gyDz1clto`)

In this case there is a JavaScript script (that might not even work on all browsers) blocking right clicks. There are so many ways to circumvent this it is quite useless:
<ul>
	<li>Use a keyboard shortcut
	<li>Disable JavaScript
	<li>Open web developer tools before navigating to this level
	<li>Get the source using `curl` or `wget`
	<li>…
</ul>

Arguably Natas is quite old and this level has not aged well.

    <!--The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi -->

## Level 2 ##

(Login: `natas2:ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi`)

The webpage source shows there is an `img` tag displaying an image, but it is a transparent 1x1 PNG, so it is invisible. More importantly, the image is at `files/pixel.png`. It is always worth checking directories - many servers will show a directory listing by default if there is not an `index.html` present (or `index.php` or any other variant).

After navigating to `http://natas2.natas.labs.overthewire.org/files/`, we can see another file, `users.txt`, with the password for the next level.

## Level 3 ##

(Login: `natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14`)

Another level that is trivial nowadays. Googling natas3 will reveal the answer immediately, but this was not the original intention. Not to mention googling any of the other level names will give you the answer for that level.

This level was supposed to work the way it is described - with search engines not being able to find the hidden information. This was accomplished using a `robots.txt` file that would tell web crawlers where to go and where not to go. So, at `http://natas3.natas.labs.overthewire.org/robots.txt`, we see:

    User-agent: *
    Disallow: /s3cr3t/

(Roughly meaning, no web crawler allowed to crawl the `s3cr3t` directory.)

So, after checking the directory and the file therein, we find the password for the next level.

## Level 4 ##

(Login: `natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ`)

This level informs us that we are not visiting from the right place. Trying to visit `natas5`, giving it the wrong username and password and then going back does not work, unfortunately.

HTTP is a stateless protocol - every single request-response cycle is a separate connection, data transfer client to server, and data transfer server to client, barring some unimportant details. This means that the "state", i.e. which page we come from must be either stored on the server, or given to the server with our request. Fortunately for us, it is the latter. Anything we give to the server we are free to modify if we want to. In particular, we are telling the server where we come from using the HTTP header called `Referer`.

There are add-ons for Chrome which allow you to modify the HTTP headers. Firefox has this functionality by default in its developer tools. Another way is to use the terminal utility `curl`:

    $ curl --basic --user natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ \
      --referer http://natas5.natas.labs.overthewire.org/ \
      http://natas4.natas.labs.overthewire.org/

(Note `--basic --user user:password` is required to make sure the server knows we are authenticated.)

This results in a page which contains the password for the next level.

## Level 5 ##

(Login: `natas5:iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq`)

In this level the server complains that we are not logged in. Once again, HTTP is a stateless protocol, so even if the exact information on who is logged in is stored server-side (quite common in practice), we need something to tell the server to look for that information - a cookie. Cookies are given to the browser by the server among its response headers and passed back to the server in the web browser's request headers.

However, in this case all the server gave us is a `loggedin` cookie. If we change its value from `0` to `1` and refresh the page, we will get the password for the next level.

Changing cookie values can easily be done in web developer tools. Application -> Storage -> Cookies in Chrome, Storage -> Cookies in Firefox.

## Level 6 ##

(Login: `natas6:aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1`)

This level is nice enough to give us its source code, censored slightly.

Note: This will become a common occurrence in natas levels. While a big "View source" link is not realistic, having the source code to a piece of software running on a server and trying to work out how to exploit it is quite common.

This source code is PHP, and it is processed and executed server-side. If the server is configured correctly, accessing a file with a `.php` extension will always result in this behaviour.

It is not necessary to know PHP (although helpful) to understand what this code does. It includes a file, checks if we have submitted any form data and if so, compares our data (submitted via HTTP POST) to a variable called `$secret`.

This file is interesting because even though it is `include`d into the PHP code, it does not have a `.php` extension. If we navigate to `http://natas6.natas.labs.overthewire.org/includes/secret.inc`, we can see the PHP code without it being executed.

From this we can see that we have to submit `FOEIUWGHFEEUHOFUOIU` in the level form.

## Level 7 ##

(Login: `natas7:7z3hEENjQtflzgnT29q7wAvMNfZdh0i9`)


We are presented with a simplistic menu. There is an important hint in the HTML source:

    <!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->

Another convention that will be kept for the entirety of natas.

Clicking on the Home and About links directs us to two different pages. Their address / URL differs only in the query parameter `page`. These are parameters parsed by the `index.php` script and sometimes referred to as GET parameters. The server will only look as far as the question mark in the URL, then delegate the rest of the work to the PHP script it executes.

If we modify the parameter in the URL ourselves, we see the script panic and throw errors which are then passed back to us in the response. Error messages (or in this case warnings) are always a useful source of information. In this case we can see (or guess) the PHP is using its `include` function to include the file we specify in its parameter. What's more, it is not checking what path we give it beforehand.

Using this knowledge and the hint given to use in the HTML comment, we navigate to `http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8` and see the password for the next level.

## Level 8 ##

(Login: `natas8:DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe`)

Here we have a simple encoding scheme. We are given an encoded version of the password (the "ciphertext") and the encoding function. We want to obtain the non-encoded version of the password (the "plaintext"). Assuming the encoding function is not a one-way (hashing or trapdoor) function, we can create a decoding function which will reverse the effects of encoding. Then applying the decoding function to the ciphertext we will get back the plaintext.

Once again, knowledge of PHP (not to mention inverse function in mathematics) is useful, but not absolutely necessary - any popular programming language will have a manual or documention source that we can refer to to understand what it is doing.

The `encodeSecret` function performs these steps (in order of operation):

 1. `base64_encode` - apply the Base-64 encoding to the input
 2. `strrev` - reverse the string
 3. `bin2hex` - encode the bytes of the string as hexadecimals

So, our `decodeSecret` should:

 1. `hex2bin` - decode hexadecimal representation into string
 2. `strrev` - reverse the string
 3. `base64_decode` - unapply the Base-64 encoding

Now in PHP:

    <?php // To denote start of PHP code
    // From the level source:
    $encodedSecret = "3d3d516343746d4d6d6c315669563362";
    // Our reversed function:
    function decodeSecret($secret) {
      return base64_decode(strrev(hex2bin($secret)));
    }
    // Print out the decoded password:
    echo decodeSecret($encodedSecret);

Running this script (e.g. `php script.php` in a terminal or using an [online REPL](https://repl.it/repls/SlowMediumblueRay)) gives us:

    oubWYf2kBq

And inputting this into the HTML form grants us access to the next level.

## Level 9 ##

(Login: `natas9:W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl`)

This level is a simple code injection. The `passthru` function in PHP simply takes its argument and lets a terminal / shell execute it verbatim. It returns the standard output. More importantly, we can supply part of the command ourselves, without it being checked or sanitised in any way. So, if we give `; cat /etc/natas_webpass/natas10;` as the input, the PHP script will execute:

    grep -i ; cat /etc/natas_webpass/natas10; dictionary.txt

The `grep` command will probably complain on the standard error (which we do not see), likewise for the `dictionary.txt` (which is not a command). However, our `cat` will print out the contents of the password we need for us.

## Level 10 ##

(Login: `natas10:nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu`)

This level is very similar to the previous one but our injection cannot contain specific characters:

    if(preg_match('/[;|&]/',$key)) {

After some light reading on `preg_match` or with some knowledge of PHP regular expressions, we can see that the above condition would trigger the error if our input contained `;` (a semicolon), `|` (a pipe), or `&amp;` (an ampersand). The square brackets specify a set of characters (the aforementioned three). The `/` slashes delimit the extent of the regular expression. Both square brackets and slashes are allowed in our injection!

So we cannot use the injection from the last level. We can, however, still put spaces in our injection. For example `"" /etc/natas_webpass/natas11` will make PHP execute:

    grep -i "" /etc/natas_webpass/natas11 dictionary.txt

That is, according to `man grep`, search for `""` (the empty string) in the files `/etc/natas_webpass/natas11` and `dictionary.txt`. The empty string is implicitly contained in any string, just like an empty set is a subset of any set. So we get `grep` outputting the contents of the password file followed by the entirety of the dictionary.

## Level 11 ##

(Login: `natas11:U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK`)

After some preliminary reading through the code, we can make a few conclusions:

 - `xor_encrypt` is some sort of XOR encryption implementation, using an unknown (censored) key.
 - Some data is stored in the cookie the server gives us.
 - By default, the data is initialised to `$defaultdata`.
 - We can provide any cookie we want (of course), but its contents will be used as the data in the script only if they are valid, i.e. they can be decrypted and JSON-decoded.

So what is the XOR encryption about? And why is there no `xor_decrypt` function?

XOR encryption is a type of encryption which takes an input and applies the XOR, exclusive or, operation on it and the key. The XOR operation operates bit-by-bit. Wherever there is a difference in the bits of the operands, it results in a 1, wherever they are the same, it results in a 0. For example:

          a = 0010 1101
          b = 0101 1001
    a xor b = 0111 0100

PHP does in fact have a `^` operator and it does work on strings as you would expect - the operation is applied on each bit, even for multi-byte strings. However, the operands need to have the same length in order to produce a result of that length, e.g.:

    "foobar" ^ "barfoo" == (6 bytes of unprintable binary data)
    "foo"    ^ "barfoo" == (3 bytes of unprintable binary data)

So the `xor_encrypt` function simply extends the key (reusing it again and again) so it can apply XOR to it and the input. You can find some very interesting pieces of information e.g. on Wikipedia about both the XOR operation and XOR encryption. Namely:

    0 xor a = a (0 is XOR identity)
    a xor a = 0
    a xor (b xor c) = (a xor b) xor c (associativity)
    a xor b = b xor a (commutativity)

Assume we have the output of the encryption, the ciphertext, as well as the input for the encryption, the plaintext. In this situation it is trivial to find the key used in the encryption:

          p = plaintext
          k = key
    E(p, k) = encryption function
          c = ciphertext
    
    c = E(p, k) = p ^ k
    p ^ c = p ^ (p ^ k) = (p ^ p) ^ k = 0 ^ k = k

In other words, if we XOR the plaintext and the ciphertext, we obtain back the key used! This is why XOR encryption is useless in the realworld unless we have a key (stream of bytes) that we only ever use once, and never again. Re-using the same key would lead to loss of security.

Back to our level - the server gives us the ciphertext (the cookie). However, if we changed nothing using the form, we know the plaintext already - it is the default data, encoded and encrypted:

    $defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");
    // ...
    function saveData($d) {
        setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
    }

The Base-64 encoding is only applied because the output of `xor_encrypt` is binary, non-printable data. After Base-64 decoding we have the actual ciphertext.

    <?php
    $defaultdata = array("showpassword" => "no", "bgcolor" => "#ffffff");
    $ciphertext = base64_decode("ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=");
    $plaintext = json_encode($defaultdata);
    echo $ciphertext ^ $plaintext;

[This PHP script](https://repl.it/repls/MediumaquamarineWindingCirriped) reveals the key used in the encryption:<p>

    qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq

So the key is `qw8J` (repeated many times to be as long as the input string). With this, we can finally modify the data ourselves, encrypt it as the server would, and give it to the server as a cookie.

    <?php
    // Copy of the encryption function with the key filled in:
    function xor_encrypt($in) {
        $key = 'qw8J';
        $text = $in;
        $outText = '';
    
        // Iterate through each character
        for($i=0;$i<strlen($text);$i++) {
        $outText .= $text[$i] ^ $key[$i % strlen($key)];
        }
    
        return $outText;
    }
    // Our modified data:
    $modified = array("showpassword" => "yes", "bgcolor" => "#ffffff");
    // After encoding:
    echo base64_encode(xor_encrypt(json_encode($modified)));

[Running this](https://repl.it/repls/WhirlwindUnevenServal) gives us:

    ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK

We set our `data` cookie to this value and refresh, and the password is revealed.

## Level 12 ##

(Login: `natas12:EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3`)

After reading through the sourcecode, we can see we will be uploading a file to the server, up to 1000 bytes in size (more than enough for us).

Of particular interest is the hidden form field called `filename`. It generates a random filename using `genRandomString()` and attaches the extension `.jpg` to it, e.g. `uh2ywqlsb9.jpg`. This filename is then passed to the server-side script, which, for some reason, creates another random string with `genRandomString()`. However, the server-side script keeps the extension passed from the client side intact!

The final thing to note is that web servers generally / by default decide how to serve clients a file based only on its extension. We noticed something similar in level 6. In this level, a file with a `.php` extension will be treated as a PHP script, so it will be executed on the server and its output will be displayed to clients.

So in short, we can perform a remote code execution attack - we create a PHP script, change the extension of the `filename` field to `.php`, and upload our script. Then we navigate to it and execute it. Our script can simply be:

    <?php readfile("/etc/natas_webpass/natas13");

([documentation](http://php.net/manual/en/function.readfile.php))

This outputs the contents of the password file to output buffer, which is what gets passed on to the client.

## Level 13 ##

(Login: `natas13:jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY`)

This level is the same as the previous one, with one exception - the file we upload is now checked using `exif_imagetype`. It seems we have to upload a valid JPEG file.

Even though we are still limited in this way, the extension vulnerability is still present, so we can upload a file and make it become a PHP script.

So what we need is a valid JPEG file that is also a valid PHP script, all under 1000 bytes. This may sound confusing, but there is one very fortunate fact about JPEG files - any data after the end of the image is simply ignored (so multiple JPEG images may be merged into one file, probably). And a fortunate fact about PHP - it simply copies data from the script file to the output buffer unless it is processing actual PHP code, which is surrounded with `<?php` and `?>` tags.

We can look for the smallest JPEG file possible (creating one with e.g. Photoshop creates a relatively huge file, because it includes a lot of unnecessary metadata). A quick search leads to [this page](https://stackoverflow.com/questions/2253404/what-is-the-smallest-valid-jpeg-file-size-in-bytes). The hexdump of a 134-byte JPEG file is:

    FF D8 FF E0 00 10 4A 46 49 46 00 01 01 01 00 48 00 48 00 00
    FF DB 00 43 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF C2 00 0B 08 00 01 00 01 01 01
    11 00 FF C4 00 14 10 01 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 FF DA 00 08 01 01 00 01 3F 10

We can use a hex editor (very useful tool in general) to convert this to binary data. In linux world, we can do:

    $ xxd -r -p > tiny.jpg

This starts the `xxd` (hexdump) program, which will await input on standard input. We paste the hexdump in, press return, and `ctrl+D` to close the input. It should create a 134-byte JPEG file in the current directory.

Then we attach our PHP script at the end of the JPEG file:

    $ printf '<?php readfile("/etc/natas_webpass/natas14");' >> tiny.jpg

The double angle bracket appends to the file instead of overwriting it. See the [Bandit write-ups](/writeups/OverTheWire-Bandit/README.md) for terminal basics.

Now we can change the form extension to `.php`, upload our `tiny.jpg` file, and it should output the password (as well as a bunch of binary garbage, which is our actual JPEG image).

## Level 14 ##

(Login: `natas14:Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1`)

(TODO!)
