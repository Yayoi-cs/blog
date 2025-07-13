# pipe_buffer

`/include/linux/pipe_fs_i.h`
```c
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```

## summary
```C
[struct pipe_buffer]                                       [struct page]

/*=========================================*/        ┌---> 0xffffea000010ee00|+0x00: 0x0100000000000000
0xffffea000010ee40  0x0000000800000000               |     0xffffea000010ee08|+0x08: 0x0000000000000000
|                   |         |                      |     0xffffea000010ee10|+0x10: 0xdead000000000122
|                   |         └-unsigned int offset  |     0xffffea000010ee18|+0x18: 0x0000000000000000
|                   └-unsigned int len;              |     0xffffea000010ee20|+0x20: 0x0000000000000000
└-struct page *page ---------------------------------┘     0xffffea000010ee28|+0x28: 0x0000000000000000
0xffffffff8221e980  0x0000000000000010                     0xffffea000010ee30|+0x30: 0x00000001ffffffff
|                             |                            0xffffea000010ee38|+0x38: 0x0000000000000000
|                             └-unsigned int flags   ┌---> 0xffffea000010ee40|+0x40: 0x0100000000000000
└-const struct pipe_buf_operations *ops              |     0xffffea000010ee48|+0x48: 0x0000000000000000
0x0000000000000000  0x0000000000000000               |     0xffffea000010ee50|+0x50: 0xdead000000000122
          |                                          |     0xffffea000010ee58|+0x58: 0x0000000000000000
          └-unsigned long private                    |     0xffffea000010ee60|+0x60: 0x0000000000000000
                                                     |     0xffffea000010ee68|+0x68: 0x0000000000000000
/*=========================================*/        |     0xffffea000010ee70|+0x70: 0x00000001ffffffff
0xffffea000010ee80  0x0000000800000000               |     0xffffea000010ee78|+0x78: 0x0000000000000000
|                   |         |                      |     
|                   |         └-unsigned int offset  |     
|                   └-unsigned int len;              |     [struct pipe_buf_operations]
└-struct page *page ---------------------------------┘                                                                                 
0xffffffff8221e980  0x0000000000000010                     0xffffffff8221e980|+0x00: 0x0000000000000000
|                             |                            0xffffffff8221e988|+0x08: 0xffffffff81292cd0  ->  0x48fa8948fa1e0ff3
|                             └-unsigned int flags         0xffffffff8221e990|+0x10: 0xffffffff81292d90  ->  0x48068b48fa1e0ff3 
└-const struct pipe_buf_operations *ops                    0xffffffff8221e998|+0x18: 0xffffffff81292b90  ->  0x48068b48fa1e0ff3 
0x0000000000000000  0x0000000000000000
          |
          └-unsigned long private

```

## allocate

### alloc_pipe_info(), kmalloc-1024
`SYSCALL_DEFINE1()->do_pipe2()->do_pipe_flags()->__do_pipe_flags()->create_pipe_files()->get_pipe_inode()->alloc_pipe_info()`

allocated when user create pipe. `pipe(p_fd)`

[](https://elixir.bootlin.com/linux/v6.14/source/fs/pipe.c#L812)
```c
// sizeof(struct pipe_buffer) == 0x28
// #define PIPE_DEF_BUFFERS	16
	unsigned long pipe_bufs = PIPE_DEF_BUFFERS;
    /* ............. */
	pipe->bufs = kcalloc(pipe_bufs, sizeof(struct pipe_buffer),
			     GFP_KERNEL_ACCOUNT);
```

### pipe_resize_ring(), arbitrary size
`set_pipe_size()->pipe_resize_ring()`

allocated when user request setting the size. `fcntl(p_fd[0], F_SETPIPE_SZ, n*0x1000)`

numbers how many `struct pipe_buffer` will be allocated depend on the `n`.
`struct pipe_buffer` is responsible for 0x1000 bytes each (page size).
since `sizeof(struct pipe_buffer) == 0x28`, size request with `0x40*0x1000` allocate 0x40 linear `struct pipe_buffer` (==0xa00 bytes, kmalloc-4098).

[](https://elixir.bootlin.com/linux/v6.6.94/source/fs/pipe.c#L1267)
```C
	bufs = kcalloc(nr_slots, sizeof(*bufs),
		       GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
```

## capability
* `struct page *page`
  * overlap page pointer->close(p_fd) let page-level UAF.
  * refer to page-jack document:[](https://i.blackhat.com/BH-US-24/Presentations/US24-Qian-PageJack-A-Powerful-Exploit-Technique-With-Page-Level-UAF-Thursday.pdf)
* `const struct pipe_buf_operations *ops`
  * falsified ops pointer with disguised vtable let control instruction pointer.

[](https://elixir.bootlin.com/linux/v6.14/source/include/linux/pipe_fs_i.h#L131)
```c
struct pipe_buf_operations {
	/*
	 * ->confirm() verifies that the data in the pipe buffer is there
	 * and that the contents are good. If the pages in the pipe belong
	 * to a file system, we may need to wait for IO completion in this
	 * hook. Returns 0 for good, or a negative error value in case of
	 * error.  If not present all pages are considered good.
	 */
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * When the contents of this pipe buffer has been completely
	 * consumed by a reader, ->release() is called.
	 */
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Attempt to take ownership of the pipe buffer and its contents.
	 * ->try_steal() returns %true for success, in which case the contents
	 * of the pipe (the buf->page) is locked and now completely owned by the
	 * caller. The page may then be transferred to a different mapping, the
	 * most often used case is insertion into different file address space
	 * cache.
	 */
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Get a reference to the pipe buffer.
	 */
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};
```

## helper
```C
int **pipe_alloc(int n_pipes) {
    int **ret = (int **)calloc(n_pipes,sizeof(int *));
    rep(i, n_pipes) {
        ret[i] = (int *)calloc(2,sizeof(int));
        SYSCHK(pipe(ret[i]));
    }
    return ret;
}

int **pipe_alloc_2(int n_pipes, int start, int end) {
    int **ret = (int **)calloc(n_pipes,sizeof(int *));
    for(int i=start;i<end;i++) {
        ret[i] = (int *)calloc(2,sizeof(int));
        SYSCHK(pipe(ret[i]));
    }
    return ret;
}

void pipe_alloc_3(int **pp, int start, int end) {
    for(int i=start;i<end;i++) {
        pp[i] = (int *)calloc(2,sizeof(int));
        SYSCHK(pipe(pp[i]));
    }
}

char *pipe_read(int *p, int len) {
    char *ret = (char *)malloc(sizeof(char)*len);
    SYSCHK(read(p[0],ret,len)); 
    return ret;
}

void pipe_write(int *p, char *buf, int len) {
    SYSCHK(write(p[1],buf,len));
}

void pipe_set_size(int *p, unsigned long sz) {
    SYSCHK(fcntl(p[0], F_SETPIPE_SZ, sz));
}

void pipe_close(int *p) {
    SYSCHK(close(p[0]));
    SYSCHK(close(p[1]));
}
```

