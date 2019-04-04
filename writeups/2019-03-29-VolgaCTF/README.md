# 2019-03-39-VolgaCTF

[website](https://q.2019.volgactf.ru)


## Challenges ##

### Crypto ###

- [x] 100 [Shadow Cat](#100-crypto--shadow-cat)
- [ ] 100 LG
- [ ] 150 Shifter
- [x] [200 Blind](#200-crypto--blind)
- [ ] 500 Beard Party



### Anti-Fake ###

- [x] [75 Fakegram star](#75-anti-fake--fakegram-star)
- [ ] 50 Horrible retelling


### Stego ###

- [x] [100 Higher](#100-stego--Higher)
- [x] [150 JOI](#150-stego--joi)


### Reverse ###

- [x] [100 PyTFM](#100-reverse--pytfm)
- [x] [250 TrustVM](#250-reverse--trustvm)
- [x] [250 JAC II](#250-reverse--jac-ii)
- [ ] 300 Online games


### PWN ###

- [x] [100 warm](#100-pwn--warm)
 

### Web ###

- [ ] 100 Shop
- [ ] 200 Blog
- [ ] 300 Gallery
- [ ] 100 Shop V.2
- [ ] 150 HeadHunter

### Anti-Joy ###

- [ ] 1 Schrödinger's task



## 100 Crypto / Shadow Cat

**Description**

> Shadow Cat
> 
> We only know that one used /etc/shadow file to encrypt important message for us.



**Files provided**

- [shadow.txt](files/shadow.txt) 
- [encrypted.txt](files/encrypted.txt)

**Solution**

(TODO)


## 200 Crypto / Blind ##

**Description**

> Blind
> Pull the flag...if you can.
>
> `nc blind.q.2019.volgactf.ru 7070`


**Files provided**

- [server.py](files/server.py)

**Solution**

Looking through the source code, there is a RSA class, with a sign and verify functions. They provide us with the n and e. The first idea was to factor n but we can see that n is quite large (617 digits) so this was a no go.


When connecting to the server, it asks for a signature and the command to execute. It does some sanitization, splits the message into signature and command and check which command to use and execute the relevant piece of the main function based on the code. 

Looking through the main function, the valid commands it takes are `ls`, `dir`, `cat`, `cd`, `leave` and `exit`. `ls` and `dir` did not have a signature check. We could use this find out where the flag is.

Running 
```bash
$ nc blind.q.2019.volgactf.ru 7070

Enter your command:
xx ls -al

drwxrwxr-x 2 root root 4096 Mar 29 18:34 .
drwxrwxr-x 3 root root 4096 Mar 29 18:35 ..
-r--r--r-- 1 root root   36 Mar 29 18:34 flag
-r--r--r-- 1 root root  620 Mar 29 18:34 private_key.py
-r-xr-xr-x 1 root root 4613 Mar 29 18:31 server.py
```

Inputting the command `xx ls -al` prints out the files in the current directory. We see that the flag file is present in the current directory. So all we need to do is cat the flag.

Initially, I tried to run `xx ls; cat flag` as we didn't need a signature check for ls. The command is sanitized using `shelex.split()` which catches semi colons and other characters and treats them as one command. So there wasn't an easy way to run two commands. So we need to sign the cat command and use it to print the flag.

Luckily we can use the `sign` command given to us. 

```bash
$ nc blind.q.2019.volgactf.ru 7070

Enter your command:
xx sign
Enter your command to sign:

```
We pass in the command we want to sign (base64 encoded) and the main function, takes decodes and splits the command using the space deliminator using the `shlex.split()`. It checks that the first word of the command passed is not `cat` or `cd`. If it is then it prints out "Invalid command". Otherwise it returns the signature of the command passed. 

In order to get around this, if we escape the space character, the `shlex.split()` function does not split on the space.

Base64 encoding `cat\ flag` gives us `Y2F0XCBmbGFn`.
Inputting this in, by passes the check as it now ignores the space between the `cat` and `flag` and returns the signature.

We can now, pass in the valid signature and the `cat flag` command and that gives us the flag.

```bash
$ nc blind.q.2019.volgactf.ru 7070

Enter your command:
xx sign
Enter your command to sign:
Y2F0XCBmbGFn
24276592954466402792157532919706447334355948690098023035375614012157378412616233865544533025515869836447793226406373271083160180523082800598281266834619631704245143244545577613294590334637358684061108293899492468337030535564036215463887905645938530571058038030943037016298964167966109577883005551522062164917343818964991120441652232394288629520079832539360872798332983684006902802429243645009242747601354050053448137191986860769673762567997572657102990869994555786984110522299362261357652756180804304984027320764350120137457095771345729635881422070403269427999652221843885023772233721400195669139542781850847904777323
Enter your command:
24276592954466402792157532919706447334355948690098023035375614012157378412616233865544533025515869836447793226406373271083160180523082800598281266834619631704245143244545577613294590334637358684061108293899492468337030535564036215463887905645938530571058038030943037016298964167966109577883005551522062164917343818964991120441652232394288629520079832539360872798332983684006902802429243645009242747601354050053448137191986860769673762567997572657102990869994555786984110522299362261357652756180804304984027320764350120137457095771345729635881422070403269427999652221843885023772233721400195669139542781850847904777323 cat flag
VolgaCTF{B1ind_y0ur_tru3_int3nti0n5}
```

`VolgaCTF{B1ind_y0ur_tru3_int3nti0n5}`


## 75 Anti-fake / Fakegram star ##

**Description**

> Fakegram star
> 
> Fake news has become a real problem for countries all over the world. To be successful in this task you have to find original sources and to be attentive to detail. When media steal news part of information might be lost.
>
> [Link](https://www.instagram.com/volgactftask/?utm_source=ig_profile_share&igshid=1wcnc8ve1nwzf)
>
> UPD Fixed bug with the flag

**Solution**
(TODO)


## 100 Stego / Higher ##

**Description**

> Higher
> 
> Take higher

**Files provided**

- [recorded.mp3](files/recorded.mp3)

**Solution**

(TODO)


## 150 Stego / JOI ##

**Description**

> JOI
> 
> All we have is just one image


**Files provided**

- [result.png](files/result.png)

**Solution**

(TODO)


## 100 Reverse / PyTFM


**Description**

> PyTFM
> 
> Can the PyTFM transformation be inverted?


**Files provided**

- [pytfm.so](files/pytfm.so)
- [transformer.py](files/transformer.py)
- [flag.enc](files/flag.enc)

**Solution**

(TODO)


## 250 Reverse / TrustVM

**Description**

> TrustVM
> 
> Files:

**Files provided**

- [data.enc](files/data.enc)

- [encrypt](files/encrypt)

- [reverse](files/reverse)

**Solution**

(TODO)

## 250 Reverse / JAC II

**Description**

> JAC II
> 
> Whenever this binary is executed it transforms the input somehow - fancy that! We've tried this with our flag and now the only file with the flag is gone 😃
>
> Can this transformation be reversed?..


**Files provided**

- [jac2](files/jac2)
- [data.jac2](files/data.jac2)

**Solution**

(TODO)


## 100 pwn / warm ##

> warm
> 
> How fast can you sove it? `nc warm.q.2019.volgactf.ru 443`

**Files provided**

- [warm](files/warm)

**Solution**

(TODO)