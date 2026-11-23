# House of Parakeet

[https://github.com/Yayoi-cs/house-of-parakeet](https://github.com/Yayoi-cs/house-of-parakeet)

Key insight: Use large bin head to bypass small bin validation.



```
house of parakeet
spray tcache
consolidate
fake chunk
[+] [OK] faker == guard_0 @ house-of-parakeet.c:42
smallbin
largebin
overwrite tcache arena
[+] [OK] large == stale @ house-of-parakeet.c:66
largebin restore
[#] largebin_head = 0x7fe051c50f98
[+] [OK] first == stale @ house-of-parakeet.c:77
alloc to largebin arena
[#] second = 0x7fe051c50fa8
```
