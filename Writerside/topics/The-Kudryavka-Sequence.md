# The Kudryavka Sequence

## challenge information
IERAE CTF2024 reversing(easy)

## analysis
attachment binary was PE.

* main
  * the omitted pseudo of main function
  * sub_1400016E0(); reads flag.png
  * sub_1400016E0(); deletes flag.png
  * sub_1400018D0(); creates statement.png
  * encrypt flag.png with the seed created with the time
  * sub_1400010D0(); encrypts the flag.png
  * Described later sub_140001650(lpBuffer, nNumberOfBytesToWrite);
![Screenshot_20250126_121917.png](Screenshot_20250126_121917.png)


* sub_140001650
  * this function shuffles the data, especially in this challenge, it shuffles the data of encrypted flag.png
  * sub_1400015D0 gives a special randomization, described later.
![Screenshot_20250126_122012.png](Screenshot_20250126_122012.png)

* sub_1400015D0
  * as you can see, there's a rand() function.
  * as I described at the first, this binary is worked on Windows, so that this rand() depends on the windows.h
  * the important things is the logic of generating the random of windows and gcc is not equal.
  * I didn't have an environment for C in windows, so I made LLM write a random function that is a same logic as the windows one.
![Screenshot_20250126_122033.png](Screenshot_20250126_122033.png)
```Py
class WindowsRand:
    def __init__(self, seed: int):
        self.seed = seed

    def rand(self):
        self.seed = (self.seed * 214013 + 2531011) & 0xFFFFFFFF
        return (self.seed >> 16) & 0x7FFF

    def srand(self, seed: int):
        self.seed = seed
```

my solution is doing brute-force of the millisecond with the file's metadata.
```Bash
[~/dc/ctf/ierae4/rev/kudryavka/distfiles] >>>exiftool flag.png.laika 
ExifTool Version Number         : 12.40
File Name                       : flag.png.laika
Directory                       : .
File Size                       : 804 KiB
File Modification Date/Time     : 2024:09:17 12:49:20+09:00
File Access Date/Time           : 2025:01:26 10:48:40+09:00
File Inode Change Date/Time     : 2024:09:23 16:12:23+09:00
File Permissions                : -rwxr-xr-x
Error                           : Unknown file type
```
by reading the file metadata, we were able to determine the file creation date and time down to the second.
there are only 1000 candidates for the seed so that brute-forcing is a practical approach.

## solver
```Py
from Crypto.Cipher import AES
from pwn import *
from tqdm import *

class WindowsRand:
    def __init__(self, seed: int):
        self.seed = seed

    def rand(self):
        self.seed = (self.seed * 214013 + 2531011) & 0xFFFFFFFF
        return (self.seed >> 16) & 0x7FFF

    def srand(self, seed: int):
        self.seed = seed

def sub_1400015D0(rander: WindowsRand, a1: int, a2: int) -> int:
    v3 = rander.rand()
    v4 = rander.rand() * v3
    return int(((rander.rand() * v4) & 0xffffffff) // (0xffffffff // (a2 - a1 + 1) + 1) + a1) & 0xffffffff

def rev_sub_140001650(a1,a2,rander: WindowsRand):
    v5s:list[int] = []
    for i in range(a2):
        v5s.append(sub_1400015D0(rander,0, a2 - 1))
    for i in reversed(range(len(v5s))):
        v5 = v5s[i]
        v3 = a1[i]
        a1[i] = a1[v5]
        a1[v5] = v3;
    return bytes(a1)

year = 2024
month = 9
day_of_week = 2
day = 17
hour = 12
minute = 49
second = 20

for i in tqdm(range(1000)):
    with open("flag.png.laika", "rb") as f:
        data = list(f.read())
    milliseconds = i
    constant = 0x200ab
    seed = (((((((((year + constant) * constant + month) * constant + day_of_week) * constant + day) 
              * constant + hour) * constant + minute) * constant + second) * constant + milliseconds) & 0xffffffff)
    print(f"Seed: {seed}")
    rand_gen = WindowsRand(seed)
    key = bytes([(rand_gen.rand() & 0xFF) for _ in range(0x20)])
    iv = bytes([(rand_gen.rand() & 0xFF) for _ in range(0x10)])
    print(f"[{hex(seed)}] key @ {len(key)} , iv @ {len(iv)}")
    print(f"Generated AES Key: {key}")
    print(f"Generated IV: {iv}")
    revData = rev_sub_140001650(data, len(data),rand_gen)
    flag_data = b""
    aeser = AES.new(key, AES.MODE_CBC, iv)
    flag_data = aeser.decrypt(bytes(revData))

    with open("out/myflag"+str(i) + ".png", "wb") as f:
        f.write(flag_data) 
```

execute the solver and I successfully decrypted the flag.png.laika

![Screenshot_20250126_130042.png](Screenshot_20250126_130042.png)
