# V4 JS RCE

> Under construction

In recent days, Telegram has been pwned many times using QuickJS memory corruption.
Inspired by this trend, I researched other applications that use a JS engine and found that PDF viewers use a JS engine to process embedded JS.
(Btw, Flare-on likes PDF embedded JS, doesn't it?)
Also, I found that Okular uses V4, which is not a major JS engine.
However, V4 has jit; it is a very high-level JS engine.

After this research, I used AI to find some memory corruptions that are reachable from PDF-embedded JS.
Then, I found an interesting memory corruption in the Qt JavaScript Engine (V4).

By using this memory corruption, I achieved 0-click RCE on Okular.

<video src="2026-11-13 03-26-05.mp4" preview-src="videoframe_7667.png"></video>

Qt doesn't accept V4 engine vulnerability triggered by malicious JavaScript. Therefore, I decided to write blog for this JS engine.

> Require malicious QML/JavaScript: Qt Qml assumes all QML and JavaScript code is provided by the application developer. Running untrusted QML code is not supported. See Handling Untrusted Data for more information.
> [https://doc.qt.io/qt-6/shared-security-model.html#issues-qt-will-not-accept](https://doc.qt.io/qt-6/shared-security-model.html#issues-qt-will-not-accept)

JS engine is funny to exploit.

I've exploited several challenges in V8 in some CTFs.
Furthermore, I achieved [LadyBird RCE using LibJS memory corruption](Exploiting-the-LadyBird-Browser.md).
Exploiting a JS engine has a bit of a different interest from other pwn challenges.

To exploit such a programming language engine, we can resolve and construct complex memory state with the exploit script itself.
This interest is similar to kernel exploits. If I sort pwn types by freedom and, effectively, by exploit scripts, it would be `JS pwn`, `kernel pwn`, and `generic TCP over exploits`.

Therefore, browsers such as Chromium and Safari use strict sandboxing that mitigates achieving real ACE from the renderer RCE. (Unfortunately, LadyBird doesn't)

JS is not used only in browsers; PDF viewers also use JS. For example, the Adobe PDF viewer uses Firefox's JS Runtime.

You can check V4 source code from: [](https://github.com/qt/qtdeclarative)

## Root cause

### 2 types of ArrayData

In the internal structure of the V4 Array, there are 2 types of ArrayData to hold variables efficiently.

- Simple
    - General array. Data are stored densely.

- Sparse
    - Tree structure to hold a sparse dataset. i.e., `array[0]=0x114514`, `array[0x4000]=0x13371337`

![Screenshot_20261115_014544.png](Screenshot_20261115_014544.png)

The conditions of `simple` -> `sparse` are:
- new index >= 0x1000
- new index >= array max index * 1.25

(refer to `src/qml/jsruntime/qv4arraydata.cpp`)

### Behavior of Array.prototype.sort()

1. `Array.prototype.sort()` converts a sparse array to a simple array if the target is a sparse array initially. This simple array will NOT register to the GC blocker array(`Scoped<ArrayData>`).
2. Then, hold swap pointers. (These pointers are scoped to the simple Array buffer)
3. Execute the registered comparison function
4. Swap if the function returned swappable

### UAF

What will happen if the registered comparison function converts a simple Array to a sparse Array and then triggers GC?

1. `Array.prototype.sort()` converts a sparse array to a simple array if the target is a sparse array initially. This simple array will NOT register to the GC blocker array(`Scoped<ArrayData>`).
2. Then, hold swap pointers. (These pointers are scoped to the simple Array buffer)
3. Execute the registered comparison function
   - example
      - Add 0 to `victim[0x8000]` → array will be sparse
      - Add large strings → trigger GC (force trigger `isAboveUnmanageHeapLimit()`, then `tryForceGCCompletion()`)

        ![Screenshot_20261115_015536.png](Screenshot_20261115_015536.png)

     - GC frees simple array, swap pointers are now dangling pointers
4. Swap if the function returned swappable → UAF swap

### Primitive Escalation, UAF swap → OOB R/W

We have UAF swap, but how can we exploit that?
My exploit epraied ArrayBuffer to reclaim UAF address as QArrayData (Qt own structure).
V4 uses QArrayData inside of simple ArrayBuffer. Therefore, the reclaim map will be

| addr          | stale simple Array | reclaimed ArrayBuffer   |
|---------------|--------------------|-------------------------|
| UAF addr+0x28 | array[0]           | QArrayDataPointer::size |
| UAF addr+0x38 | array[2]           | inline property         |

Thus, when we swap index 0 and index 2, with controllable inline property such as `reclaim_buffer.prop=0x13371337`, QArrayDataPointer::size will be falsified.
Now the UAF swap primitive become large OOB read/write.

### Addrof































