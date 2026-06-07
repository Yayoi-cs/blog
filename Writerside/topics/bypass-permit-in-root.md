# bypass permit in root

ok, now people should use bypass mode in claude instead of being machine inputting enter when digging the bug.

![Screenshot_20260422_111243.png](Screenshot_20260422_111243.png)

However, claude code block bypass permissions mode in default.

```plain text
# claude
--dangerously-skip-permissions cannot be used with root/sudo privileges for security reasons
```

Claude code had switched to elf of their script.

Before it, we can bypass the mitigation by adding `&&false` to the condition of abort in TypeScript.

Since claude code updates very often, I investigated how to bypass mitigation in easy way.

## short answer

change "getuid" string in `.dynstr` to "getpid".

LD will resolve address of the got of getuid as getpid. getpid will NOT return zero, hence, archive bypass conditions.

Launch editor in `which claude` and search for getuid, then change u to p.

