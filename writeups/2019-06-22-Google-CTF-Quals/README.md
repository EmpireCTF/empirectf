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

 - [dialtone](files/dialtone)

**Solution**

Looking at the file in IDA, we can immediately see references to some `pa_...` functions. We can confirm our suspicions with `ldd`:

```bash
$ ldd a.out 
	linux-vdso.so.1 =>  (0x00007ffd1f1b6000)
	libpulse.so.0 => /usr/lib/x86_64-linux-gnu/libpulse.so.0 (0x00007f34b722c000)
	libpulse-simple.so.0 => /usr/lib/x86_64-linux-gnu/libpulse-simple.so.0 (0x00007f34b7028000)
	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f34b6d22000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f34b6959000)
	libjson-c.so.2 => /lib/x86_64-linux-gnu/libjson-c.so.2 (0x00007f34b674e000)
	libpulsecommon-4.0.so => /usr/lib/x86_64-linux-gnu/pulseaudio/libpulsecommon-4.0.so (0x00007f34b64e7000)
	libdbus-1.so.3 => /lib/x86_64-linux-gnu/libdbus-1.so.3 (0x00007f34b62a2000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f34b6084000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f34b7678000)
	libxcb.so.1 => /usr/lib/x86_64-linux-gnu/libxcb.so.1 (0x00007f34b5e65000)
	libwrap.so.0 => /lib/x86_64-linux-gnu/libwrap.so.0 (0x00007f34b5c5b000)
	libsndfile.so.1 => /usr/lib/x86_64-linux-gnu/libsndfile.so.1 (0x00007f34b59f2000)
	libasyncns.so.0 => /usr/lib/x86_64-linux-gnu/libasyncns.so.0 (0x00007f34b57ec000)
	librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007f34b55e4000)
	libXau.so.6 => /usr/lib/x86_64-linux-gnu/libXau.so.6 (0x00007f34b53e0000)
	libXdmcp.so.6 => /usr/lib/x86_64-linux-gnu/libXdmcp.so.6 (0x00007f34b51da000)
	libnsl.so.1 => /lib/x86_64-linux-gnu/libnsl.so.1 (0x00007f34b4fc0000)
	libFLAC.so.8 => /usr/lib/x86_64-linux-gnu/libFLAC.so.8 (0x00007f34b4d8f000)
	libvorbisenc.so.2 => /usr/lib/x86_64-linux-gnu/libvorbisenc.so.2 (0x00007f34b4ae6000)
	libresolv.so.2 => /lib/x86_64-linux-gnu/libresolv.so.2 (0x00007f34b48cb000)
	libogg.so.0 => /usr/lib/x86_64-linux-gnu/libogg.so.0 (0x00007f34b46c2000)
	libvorbis.so.0 => /usr/lib/x86_64-linux-gnu/libvorbis.so.0 (0x00007f34b4497000)
```

There is a number of audio codec libraries linked but, most importantly, the [Pulse Audio library](https://www.freedesktop.org/wiki/Software/PulseAudio/), which can deal with audio input and output on Linux. Let's have a look at the decompiled `main` function:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  int result; // eax
  __int64 v5; // rax
  char v6; // [rsp+18h] [rbp-28020h]
  char v7; // [rsp+8018h] [rbp-20020h]
  int v8; // [rsp+2801Ch] [rbp-1Ch]
  int v9; // [rsp+28020h] [rbp-18h]
  char v10; // [rsp+28024h] [rbp-14h]
  unsigned int v11; // [rsp+28028h] [rbp-10h]
  int v12; // [rsp+2802Ch] [rbp-Ch]
  __int64 v13; // [rsp+28030h] [rbp-8h]

  v13 = pa_simple_new(0LL, *argv, 2LL, 0LL, "record", &ss_3811, 0LL, 0LL, &v11);
  if ( v13 )
  {
    v8 = 0;
    v9 = 0;
    v10 = 0;
    do
    {
      if ( (signed int)pa_simple_read(v13, &v6, 0x8000LL, &v11) < 0 )
      {
        v5 = pa_strerror(v11);
        fprintf(stderr, "pa_simple_read() failed: %s\n", v5);
        return 1;
      }
      x(&v6, &v7);
      v12 = r(&v8, &v7);
      if ( v12 < 0 )
      {
        fwrite("FAILED\n", 1uLL, 7uLL, stderr);
        return 1;
      }
    }
    while ( v12 );
    fwrite("SUCCESS\n", 1uLL, 8uLL, stderr);
    pa_simple_free(v13, 1LL);
    result = 0;
  }
  else
  {
    v3 = pa_strerror(v11);
    fprintf(stderr, "pa_simple_new() failed: %s\n", v3);
    result = 1;
  }
  return result;
}
```

The program connects to a pulse audio server using the [simple API](https://freedesktop.org/software/pulseaudio/doxygen/simple.html). The sample spec `ss_3811` specifies 1 channel at 44100 Hz, and the stream description is "record" - the program will try to access the microphone.

Then we have a loop, reading samples into an audio buffer (`v6`), `0x8000` bytes at a time. The `x` function is called on that audio buffer, somehow transfers data into another buffer (`v7`), then the success / failure is determined based on the second buffer in the function `r`.

Let's have a look into `x`:

```c
void __fastcall x(__int64 a1, __int64 a2)
{
  signed int v2; // [rsp+14h] [rbp-Ch]
  signed int j; // [rsp+18h] [rbp-8h]
  signed int i; // [rsp+1Ch] [rbp-4h]

  bit_flip(a1, a2);
  for ( i = 1; i <= 13; ++i )
  {
    v2 = 1 << i;
    for ( j = 0; j <= 0x1FFF; j += v2 )
      y(a2, (unsigned int)j, v2);
  }
}
```

And the accompanying `y` function:

```c
void __fastcall y(__int64 a1, __int64 a2, signed int a3)
{
  double v3; // ST48_8
  double *v4; // rax
  double v5; // ST30_8
  double v6; // ST38_8
  signed __int64 v7; // rdx
  __int128 v8; // xmm2
  __int128 v9; // xmm3
  double *v10; // rbx
  double *v11; // rbx
  signed int v12; // [rsp+10h] [rbp-60h]
  int i; // [rsp+5Ch] [rbp-14h]

  v12 = a3;
  for ( i = 0; i < v12 / 2; ++i )
  {
    cexp(a1, a2);
    v3 = -0.0 * (long double)i / (long double)v12;
    v4 = (double *)(16LL * ((signed int)a2 + i) + a1);
    v5 = *v4;
    v6 = v4[1];
    v7 = 16LL * (i + (signed int)a2 + v12 / 2);
    v8 = *(unsigned __int64 *)(v7 + a1);
    v9 = *(unsigned __int64 *)(v7 + a1 + 8);
    complex_mul(v3);
    v10 = (double *)(16LL * ((signed int)a2 + i) + a1);
    *(_QWORD *)v10 = complex_add(v5, v6, v3);
    v10[1] = v6;
    v11 = (double *)(16LL * (i + (signed int)a2 + v12 / 2) + a1);
    complex_sub(a1);
    *v11 = v5;
    v11[1] = v6;
  }
}
```

The buffer contains audio data, `x` goes through powers of 2 (`2 ** 13 == 8192`), then has a loop over samples with an inner loop in the `y` function performing complex number operations. All of these are very strong hints that we are looking at a [Fourier transform](https://en.wikipedia.org/wiki/Discrete_Fourier_transform) function.

More specifically `x` and `y` form an implementation of the [iterative Cooley-Tukey Fast Fourier Transform with bit reversal](https://en.wikipedia.org/wiki/Cooley%E2%80%93Tukey_FFT_algorithm#Data_reordering,_bit_reversal,_and_in-place_algorithms).

In simple terms, the `x` function detects the volume of individual frequencies in the audio buffer. The description of the challenge further supports this theory. With this assumption, we can clean up `main`:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 strError_; // rax
  int result; // eax
  __int64 strError; // rax
  double audioBuffer[4096]; // [rsp+18h] [rbp-28020h]
  complex fftBuffer[8192]; // [rsp+8018h] [rbp-20020h]
  state_s state; // [rsp+2801Ch] [rbp-1Ch]
  unsigned int paError; // [rsp+28028h] [rbp-10h]
  int subResult; // [rsp+2802Ch] [rbp-Ch]
  void *paServer; // [rsp+28030h] [rbp-8h]

  paServer = (void *)pa_simple_new(0LL, *argv, 2LL, 0LL, "record", &paSpec, 0LL, 0LL, &paError);
  if ( paServer )
  {
    state.field_0 = 0;
    state.field_4 = 0;
    state.field_8 = 0;
    do
    {
      if ( (signed int)pa_simple_read(paServer, audioBuffer, 0x8000LL, &paError) < 0 )
      {
        strError = pa_strerror(paError);
        fprintf(stderr, "pa_simple_read() failed: %s\n", strError);
        return 1;
      }
      fourier(audioBuffer, fftBuffer);
      subResult = r(&state, fftBuffer);
      if ( subResult < 0 )
      {
        fwrite("FAILED\n", 1uLL, 7uLL, stderr);
        return 1;
      }
    }
    while ( subResult );
    fwrite("SUCCESS\n", 1uLL, 8uLL, stderr);
    pa_simple_free(paServer, 1LL);
    result = 0;
  }
  else
  {
    strError_ = pa_strerror(paError);
    fprintf(stderr, "pa_simple_new() failed: %s\n", strError_);
    result = 1;
  }
  return result;
}
```

Now we can move on to the `r` function. There are several calls to a function called `f`, taking the result of the FFT and an integer:

```c
v8 = f(fftBuffer, 1209);
v9 = f(fftBuffer, 1336);
v10 = f(fftBuffer, 1477);
v11 = f(fftBuffer, 1633);
```

`f`:

```
double __fastcall f(complex *a1, int frequency)
{
  return cabs(a1[(frequency << 13) / 44100]);
}
```

`frequency` is given in Hertz, but then it is multiplied by `8192 / 44100`.

 - `44100` is the sampling rate - number of samples (doubles) per second recorded
 - `8192` is the size of the FFT buffer

From DFT we know that this index will represent the amplitude, i.e. [volume of the sinewave](https://en.wikipedia.org/wiki/Discrete_Fourier_transform#Motivation) (pure tone) at the given `frequency`. Let's name it `measureFrequency`.

So the `r` function measures a the loudness of various frequencies, specifically:

 - 1209, 1336, 1477, 1633
 - 697, 770, 852, 941

There are two groups, as shown above, and the maximum is picked for each. The index of the loudest frequency in the group is kept. Finally, these indices are combined into a single number `0` ... `15`.

```c
amplitudes1[0] = measureFrequency(fftBuffer, 1209);
amplitudes1[1] = measureFrequency(fftBuffer, 1336);
amplitudes1[2] = measureFrequency(fftBuffer, 1477);
amplitudes1[3] = measureFrequency(fftBuffer, 1633);
maxIndex1 = -1;
maxAmplitude1 = 1.0;
for ( i = 0; i <= 3; ++i )
{
  if ( amplitudes1[i] > maxAmplitude1 )
  {
    maxIndex1 = i;
    maxAmplitude1 = amplitudes1[i];
  }
}
amplitudes2[0] = measureFrequency(fftBuffer, 697);
amplitudes2[1] = measureFrequency(fftBuffer, 770);
amplitudes2[2] = measureFrequency(fftBuffer, 852);
amplitudes2[3] = measureFrequency(fftBuffer, 941);
maxIndex2 = -1;
maxAmplitude2 = 1.0;
for ( j = 0; j <= 3; ++j )
{
  if ( amplitudes2[j] > maxAmplitude2 )
  {
    maxIndex2 = j;
    maxAmplitude2 = amplitudes2[j];
  }
}
// ...
tone = maxIndex1 | 4 * maxIndex2;
```

There is a sequence position counter, which determines which "tone" is expected next:

```c
tone = maxIndex1 | 4 * maxIndex2;
success = 0;
switch ( state->field_4 )
{
  case 0u:
    success = tone == 9;
    goto EVALUATE;
  case 1u:
    success = tone == 5;
    goto EVALUATE;
  case 2u:
    success = tone == 10;
    goto EVALUATE;
  case 3u:
    success = tone == 6;
    goto EVALUATE;
  case 4u:
    success = tone == 9;
    goto EVALUATE;
  case 5u:
    success = tone == 8;
    goto EVALUATE;
  case 6u:
    success = tone == 1;
    goto EVALUATE;
  case 7u:
    success = tone == 13;
    goto EVALUATE;
  case 8u:
    if ( tone )
      goto EVALUATE;
    return 0;
  default:
EVALUATE:
    if ( success != 1 )
      return -1u;
    ++state->field_4;
    state->field_0 = 0;
    state->field_8 = 1;
    break;
}
```

So the tone sequence is:

    9, 5, 10, 6, 9, 8, 1, 13, 0

The final piece of the puzzle is to note the connection to phones since the challenge is called "dialtone". Searching for dialtone systems and the specific frequencies we have in the challenge leads us to [Dual-tone multi-frequency signaling](https://en.wikipedia.org/wiki/Dual-tone_multi-frequency_signaling). This system encodes numbers and symbols as combinations of two frequencies:

| -          | **1209 Hz** | **1336 Hz** | **1477 Hz** | **1633 Hz** |
| ---------- | ----------- | ----------- | ----------- | ----------- |
| **697 Hz** | 1           | 2           | 3           | A           |
| **770 Hz** | 4           | 5           | 6           | B           |
| **852 Hz** | 7           | 8           | 9           | C           |
| **941 Hz** | *           | 0           | #           | D           |

We can map all frequencies to their respective indices, then find the mapping of `tone` values to characters on a phone keypad:

| `maxIndex1` | Frequency 1 | `maxIndex2` | Frequency 2 | `tone` | Character |
| ----------- | ----------- | ----------- | ----------- | ------ | --------- |
| `0`         | 1209 Hz     | `0`         | 697 Hz      | `0`    | 1         |
| `1`         | 1336 Hz     | `0`         | 697 Hz      | `1`    | 2         |
| `2`         | 1477 Hz     | `0`         | 697 Hz      | `2`    | 3         |
| `3`         | 1633 Hz     | `0`         | 697 Hz      | `3`    | A         |
| `0`         | 1209 Hz     | `1`         | 770 Hz      | `4`    | 4         |
| `1`         | 1336 Hz     | `1`         | 770 Hz      | `5`    | 5         |
| `2`         | 1477 Hz     | `1`         | 770 Hz      | `6`    | 6         |
| `3`         | 1633 Hz     | `1`         | 770 Hz      | `7`    | B         |
| `0`         | 1209 Hz     | `2`         | 852 Hz      | `8`    | 7         |
| `1`         | 1336 Hz     | `2`         | 852 Hz      | `9`    | 8         |
| `2`         | 1477 Hz     | `2`         | 852 Hz      | `10`   | 9         |
| `3`         | 1633 Hz     | `2`         | 852 Hz      | `11`   | C         |
| `0`         | 1209 Hz     | `3`         | 941 Hz      | `12`   | *         |
| `1`         | 1336 Hz     | `3`         | 941 Hz      | `13`   | 0         |
| `2`         | 1477 Hz     | `3`         | 941 Hz      | `14`   | #         |
| `3`         | 1633 Hz     | `3`         | 941 Hz      | `15`   | D         |

Now we can map the sequence to the proper characters and put the result in `CTF{...}` (as per the challenge description) to get the flag:

`CTF{859687201}`

Just for fun, we can generate the audio signal that would produce the flag using real DTMF frequencies.

```bash
# depends on `sox` in PATH
sox -n -r 44100 -d --combine sequence \
    synth 0.1 sine 1336 sine 852 : \
    synth 0.1 sine 1336 sine 770 : \
    synth 0.1 sine 1477 sine 852 : \
    synth 0.1 sine 1477 sine 770 : \
    synth 0.1 sine 1336 sine 852 : \
    synth 0.1 sine 1209 sine 852 : \
    synth 0.1 sine 1336 sine 697 : \
    synth 0.1 sine 1336 sine 941 : \
    synth 0.1 sine 1209 sine 697
```

[Here is the generated wave file](files/dialtone.wav)

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
