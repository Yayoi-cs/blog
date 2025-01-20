# Cryptography

## interencdec
It looks encoded with base64.<br />
I decoded 2 times and got the caesar cipher text.<br />
```Bash
$ base64 -d enc_flag 
b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzg5MGsyMzc5fQ=='
```

![Image](InterRes.png)

## Custom Encryption
Write dynamic xor decrypt from 'dynamic xor encrypt' function.
```Python
from random import randint
import sys


def generator(g, x, p):
    return pow(g, x) % p


def encrypt(char, key):
    return (((ord(char) * key*311)))

def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v > 1:
        return False
    else:
        return True


def dynamic_xor_encrypt(plaintext, text_key):
    cipher_text = ""
    key_length = len(text_key)
    for i, char in enumerate(plaintext[::-1]):
        key_char = text_key[i % key_length]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        cipher_text += encrypted_char
    return cipher_text

def dynamic_xor_decrypt(cipher_text, text_key):
    decrypted_text = ""
    key_length = len(text_key)
    for i, char in enumerate(cipher_text):
        key_char = text_key[i % key_length]
        decrypted_char = chr(ord(char) ^ ord(key_char))
        decrypted_text += decrypted_char
    return decrypted_text

def test(plain_text, text_key):
    p = 97
    g = 31
    if not is_prime(p) and not is_prime(g):
        print("Enter prime numbers")
        return
    a = 90
    b = 26
    print(f"a = {a}")
    print(f"b = {b}")
    u = generator(g, a, p)
    v = generator(g, b, p)
    key = generator(v, a, p)
    b_key = generator(u, b, p)
    shared_key = None
    if key == b_key:
        shared_key = key
    else:
        print("Invalid key")
        return
    ciText = [61578, 109472, 437888, 6842, 0, 20526, 129998, 526834, 478940, 287364, 0, 567886, 143682, 34210, 465256, 0, 150524, 588412, 6842, 424204, 164208, 184734, 41052, 41052, 116314, 41052, 177892, 348942, 218944, 335258, 177892, 47894, 82104, 116314]
    xorText = ""
    for c in ciText:
        print(chr(int(c/311/shared_key)),end="")
        xorText+=chr(int(c/311/shared_key))

    print((dynamic_xor_decrypt(xorText,text_key))[::-1])


if __name__ == "__main__":
    message = "A"
    test(message, "trudeau")
```

## C3
It's an easy encryption.<br />

```Python
out = "DLSeGAGDgBNJDQJDCFSFnRBIDjgHoDFCFtHDgJpiHtGDmMAQFnRBJKkBAsTMrsPSDDnEFCFtIbEDtDCIbFCFtHTJDKerFldbFObFCFtLBFkBAAAPFnRBJGEkerFlcPgKkImHnIlATJDKbTbFOkdNnsgbnJRMFnRBNAFkBAAAbrcbTKAkOgFpOgFpOpkBAAAAAAAiClFGIPFnRBaKliCgClFGtIBAAAAAAAOgGEkImHnIl"

def reverse_lookup(out):
    lookup1 = "\n \"#()*+/1:=[]abcdefghijklmnopqrstuvwxyz"
    lookup2 = "ABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrst"

    input_chars = ""
    prev = 0

    for char in out:
        cur = lookup2.index(char)
        input_chars += lookup1[(cur + prev) % 40]
        prev = cur + prev

    return input_chars

def level2(out):
    b = 1 / 1
    for i in range(len(out)):
        if i == b * b * b:
            print(out[i],end="")
            b+=1 / 1
    print("")
print(reverse_lookup(out))

level2(out)
```

Then I got a new python code.<br />
```Python
$ python3 solve.py 
#asciiorder
#fortychars
#selfinput
#pythontwo

chars = ""
from fileinput import input
for line in input():
    chars += line
b = 1 / 1

for i in range(len(chars)):
    if i == b * b * b:
        print chars[i] #prints
        b += 1 / 1
```

Reformat it into python3 and run.<br />

```Bash
adlibs
```