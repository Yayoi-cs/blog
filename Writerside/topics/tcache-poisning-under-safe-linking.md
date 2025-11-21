# tcache-poisoning在safe-linking

## preface
Safe-linking is a security mitigation introduced in modern versions of glibc to protect tcache entries from exploitation, such as tcache poisoning. 
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
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

![Screenshot_20250217_135748.png](Screenshot_20250217_135748.png)


In CTF pwn challenges, heap operations are infrequent, so the heap state remains the same as it is locally. In such a scenario, if a heap address leak occurs, safe-linking can be easily bypassed.
tcache-poisoning is the powerful technique to get an arbitrary read/write primitive.

## calculation
Rather than storing the pointer to the next tcache entry in plaintext, glibc obscures it using a simple XOR-based transformation. The idea is to make it harder for an attacker to predict or forge valid pointers.
The transformation is defined by the macro:
```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
```
Here’s what each part means:
* pos: This is the address where the current tcache entry is stored.
* ptr: This is the actual pointer that we want to protect (usually the next pointer in the linked list).
* (size_t) pos >> 12: Shifting the address pos right by 12 bits extracts some of the higher-order bits of the address.
* XOR Operation (^): The extracted bits are then XORed with the original pointer. This operation “protects” the pointer, meaning that the stored value is not the real pointer but a transformed version.
```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  uintptr_t key;
} tcache_entry;
```

### An example of calculation
Consider two tcache bin entries for the 0x90-size bin (tcache index 7):
```py
[*]0x5fa7451e9740: 0x0000000000000000 0x0000000000000091
+->0x5fa7451e9750: 0x00005fa2bf6ac729 0xc4cdbaa3cb2ca1d4 <- tcache[idx=7,sz=0x90][6/7]
|  0x5fa7451e9760: 0x4242424242424242 0x4242424242424242
|  
|  0x5fa7451e97d0: 0x0000000000000000 0x0000000000000091
|  0x5fa7451e97e0: 0x00005fa2bf6ac6b9 0xc4cdbaa3cb2ca1d4 <- tcache[idx=7,sz=0x90][5/7]
+------------------next
   0x5fa7451e97f0: 0x4343434343434343 0x4343434343434343
```
Focus on the pointer at address `0x5fa7451e97e0`, which stores the safe-linked value `0x00005fa2bf6ac6b9`. According to our macro, this value should be computed as:
$$ 0x00005fa2bf6ac6b9 = (heap base >> 12) \oplus 0x5fa7451e9750 $$

## tcache-poisoning

For example, by rewriting the next pointer of the chunk at `heap_base` as shown below, you can force malloc to allocate memory at the location of `_IO_list_all`.
```py
(heap_base >> 12)^libc.sym["_IO_list_all"]
```

When we apply this change, the last bin in the tcache will point to libc’s `_IO_list_all`, as shown in the picture.

![Screenshot_20250217_152749.png](Screenshot_20250217_152749.png)

![Screenshot_20250217_153202.png](Screenshot_20250217_153202.png)

