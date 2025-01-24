# Anodic Music

## challenge information
Surdnlen CTF 2025: Reversing

## analysis
* main function
> Main Loop (Iterates 62 times: i = 0 to i = 61):
> 
> Dialogue Display: Calls get_dialogue() to retrieve some dialogue text and prints it using printf().
> 
> User Input: Reads a single character from stdin and stores it in the v8 buffer.  
> 
> MD5 Hash: Computes the MD5 hash of the v8 buffer using md5String(v8, v6) and stores the result in v6.  
> 
> Bank Lookup: Checks if the hash in v6 matches something in the "bank" using lookup_bank(v6, bank).  
> 
> If a match is found, a failure message is printed, and the function exits with -1.  
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *dialogue; // rax
  int i; // [rsp+Ch] [rbp-64h]
  void *v6; // [rsp+10h] [rbp-60h]
  __int64 bank; // [rsp+18h] [rbp-58h]
  __int64 v8[7]; // [rsp+20h] [rbp-50h] BYREF
  int v9; // [rsp+58h] [rbp-18h]
  __int16 v10; // [rsp+5Ch] [rbp-14h]
  unsigned __int64 v11; // [rsp+68h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  memset(v8, 0, sizeof(v8));
  v9 = 0;
  v10 = 0;
  v6 = malloc(0x10uLL);
  bank = load_bank(16LL, argv);
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  for ( i = 0; i <= 61; ++i )
  {
    dialogue = (const char *)get_dialogue();
    printf("%s", dialogue);
    *((_BYTE *)v8 + i) = getc(stdin);
    getc(stdin);
    md5String(v8, v6);
    if ( (unsigned __int8)lookup_bank(v6, bank) )
    {
      puts("There has to be some way to talk to this person, you just haven't found it yet.");
      return -1;
    }
  }
  printf("Hey it looks like you have input the right flag. Why are you still here?");
  return 0;
}
```

* load_bank
> This function loads the content of the file "hardcore.bnk" into memory and returns a pointer to a structure
```c
_QWORD *load_bank()
{
  _QWORD *result; // rax
  FILE *stream; // [rsp+0h] [rbp-20h]
  __int64 size; // [rsp+8h] [rbp-18h]
  void *ptr; // [rsp+10h] [rbp-10h]

  stream = fopen("hardcore.bnk", "rb");
  fseek(stream, 0LL, 2);
  size = ftell(stream);
  rewind(stream);
  ptr = malloc(size);
  fread(ptr, size, 1uLL, stream);
  fclose(stream);
  result = malloc(0x10uLL);
  *result = size;
  result[1] = ptr;
  return result;
}
```

* get_dialogue
> Random Dialogue Selection:
> 
> This function selects a random string from the dialogue array using /dev/urandom. The dialogue array is likely a predefined global array of strings (e.g., char *dialogue[16]).
> 
> Masking with 0xF:
> 
> Ensures the random value stays within bounds (index 0 to 15), avoiding an out-of-bounds memory access.
```c
char *get_dialogue()
{
  char ptr; // [rsp+Fh] [rbp-11h] BYREF
  FILE *stream; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  stream = fopen("/dev/urandom", "rb");
  fread(&ptr, 1uLL, 1uLL, stream);
  return (&dialogue)[ptr & 0xF];
}
```
* lookup_bank
```C
__int64 __fastcall lookup_bank(const void *a1, _QWORD *a2)
{
  __int64 i; // [rsp+18h] [rbp-8h]

  for ( i = 0LL; i < *a2 / 16LL; ++i )
  {
    if ( !memcmp(a1, (const void *)(a2[1] + 16 * i), 0x10uLL) )
      return 1LL;
  }
  return 0LL;
}
```
## solution
we can brute force flag with condition if there has already exists the hash value.
```c
    if ( (unsigned __int8)lookup_bank(v6, bank) )
    {
      puts("There has to be some way to talk to this person, you just haven't found it yet.");
      return -1;
    }
```
using recursive function to find flag with all candidate.

```py
import hashlib
import string

with open("hardcore.bnk","rb") as fd:
    bnk = fd.read()

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

def hashComp(flag:str)->bool:
    print(flag)
    res =  hashlib.md5(flag.encode()).digest() not in bnk
    return res

charset = string.ascii_letters + string.digits + string.punctuation

def brute_force(flag: str) -> bool:
    if len(flag) == 62:
        return True
    for c in charset:
        nFlag = flag + c
        if hashComp(nFlag):
            if brute_force(nFlag):
                return True
    return False

def main():
    brute_force("")

if __name__ == "__main__":
    main()
```
