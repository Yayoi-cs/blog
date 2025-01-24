# AlpacaHack Round8

## Preface
AlpacaHack Round8: https://alpacahack.com/ctfs/round-8
:::info
### quote
Welcome to AlpacaHack Round 8 (Rev)!
AlpacaHack is a new platform that hosts individual CTF competitions.

AlpacaHack Round 8 is the 8th CTF hosted by the AlpacaHack team, featuring 4 Rev challenges. The challenges are designed with a wide range of difficulties, making them enjoyable for participants of all levels, including beginners. These challenges are created by arata-nvm and sugi!
:::
I'd like to thankful for all auther who create funtastic challenges.

## masking tape
:::info
124 pts (61 solves)
Rev
Author: arata-nvm
Masking tape is also useful for flag checking :)
:::

### analysis1

![image](alpacar8_analysis1.png)



Depending on the state of the least significant bit, either the upper bits or lower bits of the flag are assigned to s2 and v8. Therefore, by performing an OR operation on the values of s2 and v8, the original value can be retrieved. By brute-forcing each character, the flag was successfully obtained.
The value of enc1 and enc2 is following.

![image](alpacar8_analysis4.png)

### solver1
```python
enc1 = [
    0x08, 0x23, 0x03, 0x03, 0x13, 0x03, 0x13, 0x03,
    0x01, 0x23, 0x31, 0x13, 0x11, 0xc8, 0x03, 0xc8,
    0x03, 0x13, 0x01, 0xc8, 0x13, 0x13, 0x03, 0x13,
    0x13, 0x11, 0x13, 0x23,
]
enc2 = [
    0x02, 0x40, 0x80, 0x08, 0x08, 0x08, 0xc8, 0xc8,
    0x80, 0x88, 0x08, 0x80, 0x88, 0x32, 0x08, 0x32,
    0x80, 0x80, 0x80, 0x32, 0x08, 0x80, 0x08, 0x08,
    0x48, 0x88, 0x80, 0xc8,
]

flag = ""
for s2, v8 in zip(enc1, enc2):
    combined = s2 | v8 
    for c in range(256):
        if (c >> 5 | (8 * c & 0xFF)) == combined:
            flag += chr(c)
            break

print(flag)
```

## hidden
:::info
192 pts (23 solves)
Rev
Author: arata-nvm
How do I hide from a decompiler?
:::

### Analysis2

![image](alpacar8_analysis2.png)

![image](alpacar8_analysis3.png)

According to the ida, each loop converts three characters of my input string.
Given that multiple characters are being transformed and instructions like ROL and ROR are involved, I determined that it would be challenging to reverse the modified correct data mathematically. Since the flag format is Alpaca{}, and I already know the beginning of the flag, brute-forcing the characters was found to be a practical approach to retrieve the flag.
By setting a breakpoint at memcmp@plt, I observed that rdi contains the converted input, while rsi contains the correct data. Comparing the memory pointed to by rdi and rsi byte by byte allowed me to identify the flag one character at a time.
Using a gdb script to automate debug, I successfully retrieved the flag. However, this solver was quite slow, taking approximately 10 minutes on my computer to find the flag. I'm looking forward to exploring other solutions!

### solver2
```python
#source solve.py
#or
#gdb -q -x solve.py [FILE]
import gdb
import time

class MemcmpBreakpoint(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec)
        self.i = 0

    def stop(self):
        rdi_value = gdb.parse_and_eval("$rdi")
        rsi_value = gdb.parse_and_eval("$rsi")
        print(f"RDI: {rdi_value}, RSI: {rsi_value}")
        for i in range(0x100):
            rdi_data = gdb.execute(f"x/c {rdi_value}+{hex(i)}", to_string=True)
            rsi_data = gdb.execute(f"x/c {rsi_value}+{hex(i)}", to_string=True)
            rdi_data = rdi_data.split()[-1]
            rsi_data = rsi_data.split()[-1]
            print(f"Value at RDI+{hex(i)}: {rdi_data}")
            print(f"Value at RSI+{hex(i)}: {rsi_data}")
            if rdi_data != rsi_data:
                self.i = i
                return True
        return True

flag = "Alpaca{"

def try_character(char):
    gdb.execute(f"start '{flag+char}'")
    #gdb.execute("start")
    gdb.execute("delete")
    memcmp_bp = MemcmpBreakpoint("memcmp@plt")
    
    gdb.Breakpoint("memcmp@plt")
    print(f"\n{flag+char}")

    gdb.execute("continue")
    
    return memcmp_bp.i

max_count = 0
charset = "abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ{}"
while(True):
    best = None
    for char in charset:
        count = try_character(char)
        print(count)
        if count > max_count:
            max_count = count
            best = char
            if char == '}':
                print(flag,end="")
                print("}")
                exit(1)
            if char != 'a':
                break

    if best == None:
        break
 
    flag += best

```

## result
![image](alpacar8_res1.png)

![image](alpacar8_res2.png)
