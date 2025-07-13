# msg_msg

`/include/linux/msg.h`
```C
/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};
```

```c
struct list_head {
	struct list_head *next, *prev;
};

struct msg_msgseg {
	struct msg_msgseg *next;
	/* the next part of the message follows immediately */
};
```

## summary

Structure of each msg depends on the size of msg data.
When the data length of `msg_msg` exceeds 0xfd0, it chains the data into a `msg_msgseg` linked list in chunks of 0xff8 bytes each.

```c
	alen = min(len, DATALEN_MSG); //DATALEN_MSG==PAGE_SIZE-sizeof(msg_msg)==0xfd0
	if (copy_from_user(msg + 1, src, alen))
		goto out_err;
		
	for (seg = msg->next; seg != NULL; seg = seg->next) {
		len -= alen;
		src = (char __user *)src + alen;
		alen = min(len, DATALEN_SEG); //DATALEN_SEG==PAGE_SIZE-sizeof(msg_msgseg)==0xff8
		if (copy_from_user(seg + 1, src, alen))
			goto out_err;
	}
```

len(data) == 0x200 <= 0xfd0

1. `msg_msg`    + 0x200 data
```C
[struct msg_msg]
0xffff88800437b1c0  0xffff88800437b1c0 
|                   |
|                   └-struct list_head *m_list.prev
└-struct list_head *m_list.next
0x0000000000000001  0x0000000000000200 
|                   |
|                   └-ssize_t m_ts
└-long m_type
0x0000000000000000  0xffff8880042ac470 
|                   |
|                   └-void *security
└-struct msg_msgseg *next
0x4141414141414141  0x4141414141414141 | data
0x4141414141414141  0x4141414141414141 |
0x4141414141414141  0x4141414141414141 v
```

len(data) == 0x2000 > 0xfd0

1. `msg_msg`    + 0xfd0 data
2. `msg_msgseg` + 0xff8 data
3. `msg_msgseg` + 0x38  data
```C
[struct msg_msg]
0xffff88800437b1c0  0xffff88800437b1c0 
|                   |
|                   └-struct list_head *m_list.prev
└-struct list_head *m_list.next
0x0000000000000001  0x0000000000002000
|                   |
|                   └-ssize_t m_ts
└-long m_type
0xffff888004380000  0xffff8880042ac470 
|                   |
|                   └-void *security
└-struct msg_msgseg *next---------------------> 0xffff888004381000  0x4141414141414141
                                                |
                                                └-struct msg_msgseg *next---------------------> 0x0000000000000000  0x4141414141414141
0x4141414141414141  0x4141414141414141 | data   0x4141414141414141  0x4141414141414141          |
0x4141414141414141  0x4141414141414141 |        0x4141414141414141  0x4141414141414141          └-struct msg_msgseg *next
0x4141414141414141  0x4141414141414141 v                                                        0x4141414141414141  0x4141414141414141
                                                                                                0x4141414141414141  0x4141414141414141
```

## allocate
msg_msg uses different allocators before and after Linux 6.11.
otherwise, msg_msgseg use kmalloc for all version.
### before Linux 6.11
[](https://elixir.bootlin.com/linux/v6.6.94/source/ipc/msgutil.c#L53)
```C
static struct msg_msg *alloc_msg(size_t len)
{
	struct msg_msg *msg;
	struct msg_msgseg **pseg;
	size_t alen;

	alen = min(len, DATALEN_MSG);
	msg = kmalloc(sizeof(*msg) + alen, GFP_KERNEL_ACCOUNT);
	if (msg == NULL)
		return NULL;
/*============================================*/

		alen = min(len, DATALEN_SEG);
		seg = kmalloc(sizeof(*seg) + alen, GFP_KERNEL_ACCOUNT);
		if (seg == NULL)
			goto out_err;
/*============================================*/
}
```

### after Linux 6.11
[](https://elixir.bootlin.com/linux/v6.16-rc5/source/ipc/msgutil.c#L64)
```C
static struct msg_msg *alloc_msg(size_t len)
{
	struct msg_msg *msg;
	struct msg_msgseg **pseg;
	size_t alen;

	alen = min(len, DATALEN_MSG);
	msg = kmem_buckets_alloc(msg_buckets, sizeof(*msg) + alen, GFP_KERNEL);
	if (msg == NULL)
		return NULL;
/*============================================*/

		alen = min(len, DATALEN_SEG);
		seg = kmalloc(sizeof(*seg) + alen, GFP_KERNEL_ACCOUNT);
		if (seg == NULL)
			goto out_err;
/*============================================*/
}
```

## free

[](https://elixir.bootlin.com/linux/v6.16-rc5/source/ipc/msgutil.c#L180)
```C
void free_msg(struct msg_msg *msg)
{
	struct msg_msgseg *seg;

	security_msg_msg_free(msg);

	seg = msg->next;
	kfree(msg);
	while (seg != NULL) {
		struct msg_msgseg *tmp = seg->next;

		cond_resched();
		kfree(seg);
		seg = tmp;
	}
}
```

## helper

```c
int *msg_prepare(int n_msg) {
    int *ret = (int *)calloc(n_msg,sizeof(int));
    rep(i, n_msg) {
        ret[i] = SYSCHK(msgget(IPC_PRIVATE, IPC_CREAT | 0666));
    }
    return ret;
}

void msg_send(int m_fd,long mtype,char *mtext,int len,int flag) {
    struct req {
        long mtype;
        char *mtext;
    } req = {
        .mtype=mtype,
        .mtext=mtext
    };
    SYSCHK(msgsnd(m_fd, &req, len, flag));
}

char *msg_recv(int m_fd, int size,int umtype,int extra_flag) {
    char *ret = (char *)calloc(size, sizeof(char));
    int flag = IPC_NOWAIT | MSG_NOERROR | extra_flag;
    struct req {
        long mtype;
        char *mtext;
    } req = {
        .mtype=0,
        .mtext=ret
    };
    SYSCHK(msgrcv(m_fd, &req, size, umtype, flag));
    return ret;
}
```
