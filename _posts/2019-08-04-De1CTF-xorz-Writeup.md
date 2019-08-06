---
layout:     post
title:      "De1CTF-xorz-Writeup"
subtitle:   " \"De1CTF-Crypto-xorz-Writeup\""
date:       2019-08-04 20:00:00
author:     "FitzBC"
header-img: "img/post-bg-2019.jpg"
catalog: true
tags:
    - CTF
    - Writeup
---

> “Yeah It's on. ”

## 前言

这两天打了一下 De1CTF 的比赛，贼菜，只出了最简单的几道题，在这里记录一下密码学的 xorz 这道题

---

## 正文

### 题目描述

题目非常简单，给了一个 python 脚本，如下：

```python
from itertools import *
from data import flag,plain

key=flag.strip("de1ctf{").strip("}")
assert(len(key)<38)
salt="WeAreDe1taTeam"
ki=cycle(key)
si=cycle(salt)
cipher = ''.join([hex(ord(p) ^ ord(next(ki)) ^ ord(next(si)))[2:].zfill(2) for p in plain])
print cipher
# output:
# 49380d773440222d1b421b3060380c3f403c3844791b202651306721135b6229294a3c3222357e766b2f15561b35305e3c3b670e49382c295c6c170553577d3a2b791470406318315d753f03637f2b614a4f2e1c4f21027e227a4122757b446037786a7b0e37635024246d60136f7802543e4d36265c3e035a725c6322700d626b345d1d6464283a016f35714d434124281b607d315f66212d671428026a4f4f79657e34153f3467097e4e135f187a21767f02125b375563517a3742597b6c394e78742c4a725069606576777c314429264f6e330d7530453f22537f5e3034560d22146831456b1b72725f30676d0d5c71617d48753e26667e2f7a334c731c22630a242c7140457a42324629064441036c7e646208630e745531436b7c51743a36674c4f352a5575407b767a5c747176016c0676386e403a2b42356a727a04662b4446375f36265f3f124b724c6e346544706277641025063420016629225b43432428036f29341a2338627c47650b264c477c653a67043e6766152a485c7f33617264780656537e5468143f305f4537722352303c3d4379043d69797e6f3922527b24536e310d653d4c33696c635474637d0326516f745e610d773340306621105a7361654e3e392970687c2e335f3015677d4b3a724a4659767c2f5b7c16055a126820306c14315d6b59224a27311f747f336f4d5974321a22507b22705a226c6d446a37375761423a2b5c29247163046d7e47032244377508300751727126326f117f7a38670c2b23203d4f27046a5c5e1532601126292f577776606f0c6d0126474b2a73737a41316362146e581d7c1228717664091c
```

代码的主要意思是说取出来 flag 中 `de1ctf{}` 之间的部分作为 `key`，然后给了一串盐值，然后明文未知，将明文的每一位和key还有盐值做异或，作为新的密文，而最终的密文已知。

### 分析

核心代码是这一行 `ord(p) ^ ord(next(ki)) ^ ord(next(si))`，密文、盐值已知，明文和 key 未知，所以直接去做逆运算是不行的。因为加密算法很简单，只是单纯的异或，所以虽然明文和 key 不知道，但是他们的异或结果是可以算出来的，所以第一步需要先计算他们的异或结果，洗掉盐值。代码如下：

```python
miwen='49380d773440222d1b421b3060380c3f403c3844791b202651306721135b6229294a3c3222357e766b2f15561b35305e3c3b670e49382c295c6c170553577d3a2b791470406318315d753f03637f2b614a4f2e1c4f21027e227a4122757b446037786a7b0e37635024246d60136f7802543e4d36265c3e035a725c6322700d626b345d1d6464283a016f35714d434124281b607d315f66212d671428026a4f4f79657e34153f3467097e4e135f187a21767f02125b375563517a3742597b6c394e78742c4a725069606576777c314429264f6e330d7530453f22537f5e3034560d22146831456b1b72725f30676d0d5c71617d48753e26667e2f7a334c731c22630a242c7140457a42324629064441036c7e646208630e745531436b7c51743a36674c4f352a5575407b767a5c747176016c0676386e403a2b42356a727a04662b4446375f36265f3f124b724c6e346544706277641025063420016629225b43432428036f29341a2338627c47650b264c477c653a67043e6766152a485c7f33617264780656537e5468143f305f4537722352303c3d4379043d69797e6f3922527b24536e310d653d4c33696c635474637d0326516f745e610d773340306621105a7361654e3e392970687c2e335f3015677d4b3a724a4659767c2f5b7c16055a126820306c14315d6b59224a27311f747f336f4d5974321a22507b22705a226c6d446a37375761423a2b5c29247163046d7e47032244377508300751727126326f117f7a38670c2b23203d4f27046a5c5e1532601126292f577776606f0c6d0126474b2a73737a41316362146e581d7c1228717664091c'
salt="WeAreDe1taTeam"
si2=cycle(salt)
miwen_after=''
for i in range(int(len(miwen)/2)): # 遍历整个密文串
    temp=miwen[i*2:i*2+2] # 步长为2
    # print(binascii.a2b_hex(temp))
    temphex_int=ord(binascii.a2b_hex(temp).decode())
    # p = chr(temphex_int ^ ord(next(si2)) ^ ord(next(ki2)))
    temp_re= hex(temphex_int ^ ord(next(si2)))[2:].zfill(2)
    miwen_after=miwen_after+temp_re
```

洗完盐值之后，这个题就比较纯粹了，通过两步来完成：1.猜解密钥长度；2.解出明文。下面来详细解释一下如何去做。

### 1。猜解密钥长度

最简单的猜解方式是爆破，枚举密钥长度，因为本题中设置了一个断言，密钥长度不会超过38，所以完全可以直接爆破。而另外一个高级一点的思路是计算密文的**汉明距离**，然后大概猜测一下密钥的位数，然后只用从排序靠前的几个密钥值中尝试枚举即可，该方法通用性较强，基本不受密钥长度限制。**汉明距离**的详细原理解释及计算实现可参考[小记一类ctf密码题解题思路](https://www.anquanke.com/post/id/161171#h3-3)。下面只是先记录一下我对于汉明距离的理解，如果对于汉明距离有一定了解，或者读完上述文章可**直接跳到[解出明文部分](#2.解出明文)**。

先来引一下 Wiki 的定义：

>在信息论中，两个等长字符串之间的汉明距离（英语：Hamming distance）是两个字符串对应位置的不同字符的个数。换句话说，它就是将一个字符串变换成另外一个字符串所需要替换的字符个数。 —— Wiki-汉明距离

举几个例子，例如：

* 10<font color=blue>1</font>1<font color=blue>1</font>01 与 10<font color=red>0</font>1<font color=red>0</font>01 之间的汉明距离是2。
* 2<font color=blue>14</font>3<font color=blue>8</font>96 与 2<font color=red>23</font>3<font color=red>7</font>96 之间的汉明距离是3。
* "<font color=blue>t</font>o<font color=blue>n</font>e<font color=blue>d</font>" 与 "<font color=red>r</font>o<font color=red>s</font>e<font color=red>s</font>" 之间的汉明距离是3。

所以，汉明距离可以表示字符之间的相似性程度，那对于我们求解密钥长度有什么帮助呢。是因为所有的可打印字符其实都有它对应的 ASCII 值，大写 A-Z 的 ASCII 值是 65-90，小写 a-z 的 ASCII 值是 97-122。65 的二进制表示是01000001，01011010，字母的汉明距离平均是2-3，任意字符（非纯字母）的两两汉明距离平均为4，那么虽然我们不知道明文，但是可以计算两两字母之间汉明距离，如果使用了正确的密钥长度，那么整个密文的汉明距离应该较小（不一定是最小，排除误差。因为明文都是可打印字符，汉明距离比较接近，而如果是一堆不可打印字符，他们的汉明距离可能较大）。所以通过计算汉明距离即可猜测出密钥的有限可能长度。代码参考[小记一类ctf密码题解题思路](https://www.anquanke.com/post/id/161171#h3-3)。

```python
normalized_distances = []

for KEYSIZE in range(2, 40):
    #我们取其中前6段计算平局汉明距离
    b1 = b[: KEYSIZE]
    b2 = b[KEYSIZE: KEYSIZE * 2]
    b3 = b[KEYSIZE * 2: KEYSIZE * 3]
    b4 = b[KEYSIZE * 3: KEYSIZE * 4]
    b5 = b[KEYSIZE * 4: KEYSIZE * 5]
    b6 = b[KEYSIZE * 5: KEYSIZE * 6]

    normalized_distance = float(
        hamming_distance(b1, b2) +
        hamming_distance(b2, b3) +
        hamming_distance(b3, b4) +
        hamming_distance(b4, b5) +
        hamming_distance(b5, b6)
    ) / (KEYSIZE * 5)
    normalized_distances.append(
        (KEYSIZE, normalized_distance)
    )
normalized_distances = sorted(normalized_distances,key=lambda x:x[1])
```

### 2.解出明文

因为是 Writeup，所以直接分为两部分，第一部分为比赛思路。即如果没有什思路的话，可以找到类似的题目，快速将题目问题转换为相似题目问题，然后参考别人 Writeup 思路，快速解决，不去细究其算法原理（尤其是密码学）。第二部分为详细算法解释。

#### 比赛思路

因为已经找到类似题目解题思路——[小记一类ctf密码题解题思路](https://www.anquanke.com/post/id/161171#h3-3)，故只需要复现即可。本题和该解题思路的区别就是加入了盐值，而第一步我们已经将盐值洗去，所以问题已经基本转换过来，可以直接用其 Writeup 中的代码，稍加修改即可完成解出明文过程。详细代码见[完整解题代码](#完整解题代码)

#### 详细算法解释



## 附：完整解题代码

```python
import base64
import binascii
import base64
import string
from itertools import *

def bxor(a, b):     # xor two byte strings of different lengths
    if len(a) > len(b):
        return bytes([x ^ y for x, y in zip(a[:len(b)], b)])
    else:
        return bytes([x ^ y for x, y in zip(a, b[:len(a)])])

def hamming_distance(b1, b2):
    differing_bits = 0
    for byte in bxor(b1, b2):
        differing_bits += bin(byte).count("1")
    return differing_bits

# text = ''
# with open("6.txt","r") as f:
#     for line in f:
#         text += line


# b = base64.b64decode(text)

def break_single_key_xor(text):
    key = 0
    possible_space=0
    max_possible=0
    letters = string.ascii_letters.encode('ascii')
    for a in range(0, len(text)):
        maxpossible = 0
        for b in range(0, len(text)):
            if(a == b):
                continue
            c = text[a] ^ text[b]
            if c not in letters and c != 0:
                continue
            maxpossible += 1
        if maxpossible>max_possible:
            max_possible=maxpossible
            possible_space=a
    key = text[possible_space]^ 0x20
    return chr(key)


miwen='49380d773440222d1b421b3060380c3f403c3844791b202651306721135b6229294a3c3222357e766b2f15561b35305e3c3b670e49382c295c6c170553577d3a2b791470406318315d753f03637f2b614a4f2e1c4f21027e227a4122757b446037786a7b0e37635024246d60136f7802543e4d36265c3e035a725c6322700d626b345d1d6464283a016f35714d434124281b607d315f66212d671428026a4f4f79657e34153f3467097e4e135f187a21767f02125b375563517a3742597b6c394e78742c4a725069606576777c314429264f6e330d7530453f22537f5e3034560d22146831456b1b72725f30676d0d5c71617d48753e26667e2f7a334c731c22630a242c7140457a42324629064441036c7e646208630e745531436b7c51743a36674c4f352a5575407b767a5c747176016c0676386e403a2b42356a727a04662b4446375f36265f3f124b724c6e346544706277641025063420016629225b43432428036f29341a2338627c47650b264c477c653a67043e6766152a485c7f33617264780656537e5468143f305f4537722352303c3d4379043d69797e6f3922527b24536e310d653d4c33696c635474637d0326516f745e610d773340306621105a7361654e3e392970687c2e335f3015677d4b3a724a4659767c2f5b7c16055a126820306c14315d6b59224a27311f747f336f4d5974321a22507b22705a226c6d446a37375761423a2b5c29247163046d7e47032244377508300751727126326f117f7a38670c2b23203d4f27046a5c5e1532601126292f577776606f0c6d0126474b2a73737a41316362146e581d7c1228717664091c'
salt="WeAreDe1taTeam"
si2=cycle(salt)
miwen_after=''
for i in range(int(len(miwen)/2)):
    temp=miwen[i*2:i*2+2]
    # print(binascii.a2b_hex(temp))
    temphex_int=ord(binascii.a2b_hex(temp).decode())
    # p = chr(temphex_int ^ ord(next(si2)) ^ ord(next(ki2)))
    temp_re= hex(temphex_int ^ ord(next(si2)))[2:].zfill(2)
    miwen_after=miwen_after+temp_re



b=binascii.a2b_hex(miwen_after)

normalized_distances = []


for KEYSIZE in range(2, 40):
    #我们取其中前6段计算平局汉明距离
    b1 = b[: KEYSIZE]
    b2 = b[KEYSIZE: KEYSIZE * 2]
    b3 = b[KEYSIZE * 2: KEYSIZE * 3]
    b4 = b[KEYSIZE * 3: KEYSIZE * 4]
    b5 = b[KEYSIZE * 4: KEYSIZE * 5]
    b6 = b[KEYSIZE * 5: KEYSIZE * 6]

    normalized_distance = float(
        hamming_distance(b1, b2) +
        hamming_distance(b2, b3) +
        hamming_distance(b3, b4) +
        hamming_distance(b4, b5) +
        hamming_distance(b5, b6)
    ) / (KEYSIZE * 5)
    normalized_distances.append(
        (KEYSIZE, normalized_distance)
    )
normalized_distances = sorted(normalized_distances,key=lambda x:x[1])


for KEYSIZE,_ in normalized_distances[:5]:
    block_bytes = [[] for _ in range(KEYSIZE)]
    for i, byte in enumerate(b):
        block_bytes[i % KEYSIZE].append(byte)
    keys = ''
    try:
        for bbytes in block_bytes:
            keys += break_single_key_xor(bbytes)
        key = bytearray(keys * len(b), "utf-8")
        plaintext = bxor(b, key)
        print("keysize:", KEYSIZE)
        print("key is:", keys, "n")
        s = bytes.decode(plaintext)
        print(s)
    except Exception:
        continue
```
