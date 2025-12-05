# A64Fx knowledge

こんにちは, 18歳学生です. 自己紹介は他のブログを観察してください.

1人アドベントカレンダーも開催しています. [](Advent-Calender-2025.md)

ここでは夏に理化学研究所で富岳を触りまくったので一般に知られている知見についてまとめようと思います.

## preface
A64Fxとはスパコン富岳に積まれているFujitsu製のCPUである.

スパコンでは珍しくaarch64が採用されている. 昨今googleやamazonのデータセンターでarmプロセッサーへの移行が進んでいるが一足先にarmが採用されたプロセッサである.

aarch64のスパコンそのものが~~珍しい~~はずだった... NvidiaのDGX SuperPodにはArmの独自cpuが乗っているため, 世の中のスパコンがどんどんarmに移行してきているのかもしれない.

個人的にarmのアセンブリはあまりにも可読性にかけるため,x86_64の存命に期待している.

## docs

A64Fxのありがたい点としてプロセッサの情報がghにpdfで上がっている.

[](https://github.com/fujitsu/A64FX/tree/master/doc)

[](https://www.fujitsu.com/downloads/JP/jsuper/a64fx/a64fx_datasheet_jp.pdf)

大事そうな情報だけまとめよう
- SVE, SVE2に対応
- SIMD幅は512bit
- `movprfx`命令のデコードが特殊
- freqは1.8GHz,2.0GHz, 2.2GHz,2.6GHz固定

ここで人類が驚くべきはSIM幅が512bitであることだ. どこかの中途半端な~~intel~~のAVX512とは違い, というかSVEのsimd幅は可変なので256も128もアリ得るが素晴らしいレジスタサイズである.

残念ながらSMEには非対応, 富岳Nextに積まれる予定のCPU, `FUJITSU- MONOKA-X`でSMEに対応するとのことで非常に期待している. [](https://www.riken.jp/pr/news/2025/20250822_1/index.html)

> SIMDとは?
> 
> SIMDとは1つの命令で複数のデータを同時に処理することができる技術で例えば8つの浮動小数点を一回で四則演算できたり,同じ演算を複数のデータに対して行うときに凄まじい並列性を発揮できる.

また,CPU周波数が固定であることは研究的にすごくありがたいことで関数のレイテンシにFreqをかけることで関数1回あたりにかかるCPUクロック数を測定出来たりする.

## SVE 101
armのintrinsicsガイドが非常に強力: [](https://developer.arm.com/architectures/instruction-sets/intrinsics/)

まず, 前述の通りSVEのsimd幅は可変なので`vlen`を使ってSIMD幅を獲得する. [](https://developer.arm.com/architectures/instruction-sets/intrinsics/#q=vlen)

あと重要な要素としてpredicate registerが存在する. 皆様,特に本校の学生さんのマシンは大体x64でAVXを組む人がいると思うがこのような概念はないので若干戸惑うと思う.

macを使っている人もいるだろうがmacを使っている人なんて意識が高くて低レイヤののアセンブリを見たことがないのでpredicate registerについて知見がないと思う.

> predicate registerとは?
> 
> predicate registerとはSVEのどのベクトルに対して演算を実行するかを制御するマスクレジスタである. 
> bit flagが立っていて例えばforでSIMDを回すときに $n\mod vlen != 0$なときにマスクレジスタでpredicate registerをマスクすることで処理するベクトルの個数を調整出来たりする.
> 
> predicate registerの導入によりSVEではsimd幅が可変でも動く. やりますねぇ.
> intrinsicsでいうと`svwhilelt_b64`などで設定する. [](https://developer.arm.com/architectures/instruction-sets/intrinsics/#q=svwhilelt)
> 
> [The ARM Scalable Vector Extension](https://arxiv.org/pdf/1803.06185)
> 
> [Arm可伸缩性向量扩展-SVE（上）](https://aijishu.com/a/1060000000350714)
> 
> [ARM - SVE 介绍](https://www.cnblogs.com/wenbinteng/p/19052964)

- example: ある関数`func`を呼び出し,返り値を加算し続けるforループ

```cpp
const std::size_t vlen = svcntd();
svfloat64_t sum = svdup_f64(0.0);
for (std::size_t i = 0; i < SIZE; i += vlen) {
    svbool_t active = svwhilelt_b64(i, SIZE);
    svfloat64_t x = svld1_f64(active, &data_ptr[i]);
    sum=svadd_f64_x(active,sum, func(x,active));
}
return sum;
```

- fyi: avx version

```CPP
__m256d sum = _mm256_setzero_pd();
for (std::size_t i = 0; i < SIZE; i += 4) {
    __m256d x = _mm256_load_pd(&data_ptr[i]);
    sum = _mm256_add_pd(sum, func(x));
}
return sum;
```

predicate registerをマスターすればあとはAVXと同じ感じで計算ができる.

他に注意することがあるとすればSVEのintrinsicsは引数に符号を渡せないので`sub(a,b)`を`add(a,-b)`でサボることが出来なかったり,
FMA($a*b+c$)の計算では以下のようなintrinsicsを使い分ける必要がある.

```CPP
svmls[_f64]_m	op1[i] - op2[i] * op3[i]
svmla[_f64]_m	op1[i] + op2[i] * op3[i]
svnmla[_f64]_m	-(op1[i] + op2[i] * op3[i])
svnmls[_f64]_m	-(op1[i] - op2[i] * op3[i])
```

FMA($a*b+c$)自体はCPUのパイプライン並列性を考えるときに採用できるならしたほうがいいので,画面前のそこのあなたも画面後ろのそこのあなたもこの苦行を味わう日も近いのかもしれない.

## tips

### movを減らす

例えば,x86_64で考えてみよう.
```c
puts("hello world");
```
これをgccでノーオプションでコンパイルすると以下のようなアセンブリになるはずだ.
```C
mov rax,[rip+0x114514] #<-ptr of "hello world" in .rodata
mov rdi, rax
call puts@plt
```
gccのO3とかでコンパイルするとrdiに直接ロードされるようになると思う.
```c
mov rdi,[rip+0x114514] #<-ptr of "hello world" in .rodata
call puts@plt
```
movという命令は前後命令への依存度が高いのでパイプラインへの悪影響を与える.

これをSVEで考えると`ld1rd`命令が該当する.
`ld1rd`命令は低数値を全てのレーンにロードする命令で,ループで定数値をかけていくときに素晴らしいレイテンシを達成できる.
[](https://developer.arm.com/documentation/111182/2025-09_ASL1/SVE-Instructions/LD1RD--Load-and-broadcast-doubleword-to-vector-)

富岳のコンパイラFCCで普通にコンパイルするとスカラーレジスタに値を書き込んでからベクトルレジスタに値を移すような処理を見るかもしれないがそれを`ld1rd`命令によって解消できる.
p117.[A64FX_Microarchitecture_Manual_en_1.0.pdf](https://github.com/fujitsu/A64FX/blob/master/doc/A64FX_Microarchitecture_Manual_en_1.0.pdf)以降にはSVE命令のA64FXでのレイテンシが書かれているので参考にすると良いだろう

ld1rdについて仕様を確認するとld1rdはEAG,単一パイプラインのみを使用する. A64Fxはパイプラインが2つあるのでld1rdを利用することでさらなるパイプライン並列性を確保することができる.
- ld1rd
  - 11
  - EAG


A64Fxでは`movprfx`命令が最適化されている(p14,p32. [A64FX_Microarchitecture_Manual_en_1.0.pdf](https://github.com/fujitsu/A64FX/blob/master/doc/A64FX_Microarchitecture_Manual_en_1.0.pdf))



## ref

- [](https://www.cnblogs.com/wenbinteng/p/19040667)
- [](https://www.cnblogs.com/wenbinteng)
- [](https://www.arm.com/)
- [](https://github.com/fujitsu/A64FX/blob/master/doc/A64FX_Microarchitecture_Manual_en_1.0.pdf)
- [](https://www.cnblogs.com/wenbinteng/p/19040115)
- [](https://blog.csdn.net/sinat_32960911/article/details/139664387)
- [](https://blog.csdn.net/AngelLover2017/article/details/124808387?utm_medium=distribute.pc_relevant.none-task-blog-2~default~baidujs_baidulandingword~default-0-124808387-blog-139664387.235^v43^pc_blog_bottom_relevance_base4&spm=1001.2101.3001.4242.1&utm_relevant_index=3)
- [](https://arxiv.org/pdf/1803.06185)
- [](https://aijishu.com/a/1060000000350714)
- [](https://lxjk.github.io/2020/02/07/Fast-4x4-Matrix-Inverse-with-SSE-SIMD-Explained-JP.html)



