# 2019-06-22-Google-CTF-Quals #

[CTFTime link](https://ctftime.org/event/809) | [Website](https://capturetheflag.withgoogle.com1/)

---

## Challenges ##

### Reversing ###

 - [231 Flaggy Bird]
 - [189 Dialtone]
 - [140 Malvertising](#140-reversing--malvertising)

---

## 231 Reversing / Flaggy Bird ##

**Description**

> Overcome insurmountable obstacles then find the secret combination to get the flag.

**Files provided**

 - flaggy-bird.apk

**Solution**

## 189 Reversing / Dialtone ##

**Description**

> You might need a pitch-perfect voice to solve this one. Once you crack the code, the flag is CTF{code}.

**Files provided**

 - dialtone

**Solution**

## 140 Reversing / Malvertising ##

**Description**

> Unravel the layers of malvertising to uncover the Flag
> 
> https://malvertising.web.ctfcompetition.com/

**No files provided**

**Solution**

Upon visiting the website, we are greeted with a fake YouTube page with an ad. All of it is just a static background image, except for the ad, which seems legit enough for uBlock to block it. Before diving into the ad itself, we note that the logo says "YouTube <sup>CA</sup>". Canada?

The ad frame links to [`ads/ad.html`](files/malvertising1.html).

This file has some standard ad stuff, but more importantly links to a [JavaScript file](files/malvertising2.js):

```html
<script id="adjs" src="./src/metrics.js" type="text/javascript"></script>
```

Running the code through a [JavaScript beautifier](https://beautifier.io/) (result [here](files/malvertising2-b.js)), we can see a couple of top-level sections. The first starts with an immediately invoked anonymous function:

```js
! function(a, b, c) {
  "undefined" != typeof module && module.exports ? module.exports = c() :
    "function" == typeof define && define.amd ? define(c) : b[a] = c()
}("steg", this, function() {
  // ...
});
```

This seems like a universal module loader, compatible with CommonJS (`module.exports`), AMD (`define`), as well as browsers (`b[a] = c()` results in `this["steg"] = c()`, where `this` is just `window` here). The `steg` module defines some basic maths functions for dealing with primes, as well as an `encode` and `decode` function that accepts an image.

Next, there is a number of Base-64 strings in the `a` array. They decode to binary garbage, so they are probably encrypted. There are also several instances of code like `b("0x1", "...")`. The first number is always a hexadecimal integer (presumably an index in the `a` array), the second is always a four-character key. By modifiying the (unformatted) code to not do anything at the end but instead to [dump the decoded strings](scripts/malvertising2.html), we get the following listing:

```
b('0x0','Kb10')  => apply
b('0x1',')ID3')  => return (function() 
b('0x2','3hyK')  => {}.constructor("return this")( )
b('0x3','^aQK')  => console
b('0x4','bxQ9')  => console
b('0x5','bxQ9')  => log
b('0x6','vH0t')  => warn
b('0x7','bxQ9')  => debug
b('0x8','jAUm')  => info
b('0x9','SF81')  => exception
b('0xa','$KuR')  => trace
b('0xb','IfD@')  => console
b('0xc','%RuL')  => console
b('0xd','e9PJ')  => warn
b('0xe','(fcQ')  => console
b('0xf','xBPx')  => info
b('0x10','yDXL') => console
b('0x11','IDtv') => error
b('0x12','oBBn') => console
b('0x13','^aQK') => exception
b('0x14','F#*Z') => console
b('0x15','vH0t') => trace
b('0x16','%RuL') => constructor
b('0x17','jAUm') => getElementById
b('0x18','3hyK') => adimg
b('0x19','F#*Z') => onload
b('0x1a','OfTH') => decode
b('0x1b','JQ&l') => test
b('0x1c','IfD@') => userAgent
```

After the `b` function, there are three functions which seem to be anti-debugger, since they cause infinite loops and replace `console` functions. Finally, after replacing all the `b` calls, we come to the final part of the `metrics.js` script:

```js
var s = 'constructor';
var t = document['getElementById']('adimg');
t['onload'] = function() {
  try {
    var u = steg['decode'](t);
  } catch (v) {}
  if (Number(/android/i ['test'](navigator['userAgent']))) {
    s[s][s](u)();
  }
};
```

The `s[s][s]` bit is basically `eval`:

```js
>>> s
"constructor"
>>> s[s]
ƒ String() { [native code] }
>>> s[s][s]
ƒ Function() { [native code] }
```

`u`, the result of the steganography decoding of the `adimg` picture is executed if `android` is found in the visitor's `User-Agent` string. The result of the decoding is (with minor formatting adjustments):

```js
var dJs = document.createElement('script');
dJs.setAttribute('src','./src/uHsdvEHFDwljZFhPyKxp.js');
document.head.appendChild(dJs);
```

We can run [the linked file](files/malvertising3.js) through the beautifier once again to get something [nicer](files/malvertising3-b.js). In this file, we have a set of functions in the `T` object, some polyfills for `String`, and then:

```js
function dJw() {
  try {
    return navigator.platform.toUpperCase().substr(0, 5)
    + Number(/android/i.test(navigator.userAgent))
    + Number(/AdsBot/i.test(navigator.userAgent))
    + Number(/Google/i.test(navigator.userAgent))
    + Number(/geoedge/i.test(navigator.userAgent))
    + Number(/tmt/i.test(navigator.userAgent))
    + navigator.language.toUpperCase().substr(0, 2)
    + Number(/tpc.googlesyndication.com/i.test(document.referrer) || /doubleclick.net/i.test(document.referrer))
    + Number(/geoedge/i.test(document.referrer))
    + Number(/tmt/i.test(document.referrer))
    + performance.navigation.type
    + performance.navigation.redirectCount
    + Number(navigator.cookieEnabled)
    + Number(navigator.onLine)
    + navigator.appCodeName.toUpperCase().substr(0, 7)
    + Number(navigator.maxTouchPoints > 0)
    + Number((undefined == window.chrome) ? true : (undefined == window.chrome.app))
    + navigator.plugins.length
  } catch (e) {
    return 'err'
  }
};
a = 
  "A2xcVTrDuF+EqdD8VibVZIWY2k334hwWPsIzgPgmHSapj+zeDlPqH/RHlpVCitdlxQQfzOjO01xCW/6TNqkciPRbOZsizdYNf5eEOgghG0YhmIplCBLhGdxmnvsIT/69I08I/ZvIxkWyufhLayTDzFeGZlPQfjqtY8Wr59Lkw/JggztpJYPWng=="
eval(T.d0(a, dJw()));
```

The Base64 string `a` seems encrypted (binary garbage when decoded). Based on this we can easily guess that `T.d0` is a decryption function using the result of the `dJw()` call as a key.

The key is a sort of browser fingerprint, constructed out of a number of checks. All `Number(...)` calls in the function take a boolean value and change it to `0` or `1`.

 - `LINUX` / `WIN32` / `MACIN` / ... - [`navigator.platform.toUpperCase().substr(0, 5)`](https://developer.mozilla.org/en-US/docs/Web/API/NavigatorID/platform) - the first five letters of the uppercased navigator platform
 - `0` / `1` - is `android` part of the [user agent](https://developer.mozilla.org/en-US/docs/Web/API/NavigatorID/userAgent) string?
 - `0` / `1` - is `AdsBot` part of the user agent string?
 - `0` / `1` - is `Google` part of the user agent string?
 - `0` / `1` - is `geoedge` part of the user agent string?
 - `0` / `1` - is `tmt` part of the user agent string?
 - `EN` / `FR` / `SK` / ... - [`navigator.language.toUpperCase().substr(0, 2)`](https://developer.mozilla.org/en-US/docs/Web/API/NavigatorLanguage/language) - the first two letters of the uppercased navigator language
 - `0` / `1` - did the user [come from a URL](https://developer.mozilla.org/en-US/docs/Web/API/Document/referrer) containing either `tpc.googlesyndication.com` or `doubleclick.net`?
 - `0` / `1` - did the user come from a URL containing `geoedge`?
 - `0` / `1` - did the user come from a URL containing `tmt`?
 - `0` / `1` / `2` / `255` - [how did the user navigate](https://developer.mozilla.org/en-US/docs/Web/API/PerformanceNavigation/type) to the page?
 - `0` / `1` / ... - [how many redirections](https://developer.mozilla.org/en-US/docs/Web/API/PerformanceNavigation/redirectCount) did the user go through before getting to the page?
 - `0` / `1` - are [cookies enabled](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/cookieEnabled)?
 - `0` / `1` - does the browser [think it is online](https://developer.mozilla.org/en-US/docs/Web/API/NavigatorOnLine/onLine)?
 - `MOZILLA` - the uppercased [`appCodeName`](https://developer.mozilla.org/en-US/docs/Web/API/NavigatorID/appCodeName) (which is always `Mozilla`)
 - `0` / `1` - does the browser [support any number of touch points](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/maxTouchPoints)? (is it a touchscreen?)
 - `0` / `1` - is the user NOT on a Chromium-based browser?
 - `0` / `1` / ... - number of [installed plugins](https://developer.mozilla.org/en-US/docs/Web/API/NavigatorPlugins/plugins)

Furthermore, it seems that even though this fingerprint can generate strings of 31 characters (or even longer due to `redirectCount` and `plugins.length`), only the first 16 characters are used as the decryption key.

Due to the various constant numbers in the `T` object, e.g. `2654435769 == 0x9E3779B9`, we can guess it is an implementation of the [Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm).

So we have a ciphertext, a decryption method, and the general layout of the key with a rather limited keyspace. With the assumption that the challenge would actually decrypt and run successfully from beginning to end for *some* real user agent, we can also use two pieces of information we gathered before:

 - the user agent string must contain `android` - we can fix `navigator.platform.toUpperCase().substr(0, 5)` to be `LINUX`
 - the YouTube page indicated a Canadian region code - we can fix `navigator.language.toUpperCase().substr(0, 2)` to be `EN` or `FR` (`navigator.language` would be e.g. `fr_CA`)

What remains is 9 characters (`16 - "LINUX".length - "EN".length`) all of which can be `0` or `1`, except the last one, which can also be `2`. Just 1536 possibilities, very quick to brute-force.

> And here is where our team hit a snag - we wrote a decryption script and run it in Node.JS, but it produced no results. We expanded the brute-force to be quite exhaustive, trying different values for `navigator.platform`, hundreds of possible language codes, nothing produced any code. It turns out the decryption code as-is simply does not function identically on Node.JS. Running the brute-force script on a browser leads to the next stage in a matter of seconds. We did not manage to think of this during the CTF, which cost us the flag. What follows is a write-up of steps taken after the CTF.

[Full decryption script here](scripts/malvertising3.html)

With the key `LINUX10000FR1000`, we get:

```js
var dJs = document.createElement('script');
dJs.setAttribute('src','./src/npoTHyBXnpZWgLorNrYc.js');
document.head.appendChild(dJs);
```

Yet again we take [the file](files/malvertising4.js) and [beautify it](files/malvertising4-b.js). We can see the same patterns of encoding as in the previous stage (array of Base64-encoded strings, 4-character keys, multiple functions to prevent debugging). However, this time we need only load the JS file locally as-is in a browser with the console closed, *then* open the console to see an error - the JS file tries to load the file `WFmJWvYBQmZnedwpdQBU.js`!

And that file simply contains the flag:

```js
alert("CTF{I-LOVE-MALVERTISING-wkJsuw}")
```

The last stage contained references to RTC/STUN servers, which may have been interesting to (try to) reverse, but it would be wasted effort!

`CTF{I-LOVE-MALVERTISING-wkJsuw}`
