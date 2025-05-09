# findruction

findruction is instruction finder written in rust.

You can find some instruction from large binary with this tool in millisecond.

findruction has assembler inside it, so you need to just hand over the target assembly.

[](https://github.com/Yayoi-cs/findruction)

## example
### find `swapgs` from `vmlinux` with disassembly
In recent kernel, rop gadget tool such as `ropr` doesn't detect `swapgs` gadget because simply `swapgs; ret;` were disappeared. :cry:

Here's how you search `swapgs` from `vmlinux` and check disassembly around them.

![Screenshot_20250506_224901.png](Screenshot_20250506_224901.png)


### find `iretq` from `vmlinux` without disassembly
Next, let's check out the result when we wanna search `iretq`. We don't need disassembly so simply add `-n` option and here's the result of it.

![Screenshot_20250506_232839.png](Screenshot_20250506_232839.png)

It took only 51.19ms. Of course, all result were piked out from only executable section in the `vmlinux` .

## usage
```shell
$ findruction --help
Usage: findruction [OPTIONS] --file <FILE> --asm <ASM>

Options:
  -f, --file <FILE>  
  -a, --asm <ASM>    
  -n, --no-disass    
  -h, --help         Print help
  -V, --version      Print version
```

## install
```shell
git clone https://github.com/Yayoi-cs/findruction
cd findruction
cargo build --release
echo "export PATH=$PATH:$(pwd)/target/release/" >> ~/.bashrc
```