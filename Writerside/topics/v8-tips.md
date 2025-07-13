# v8 tips

## Building d8

### Resources
depot_tools.git: [](https://chromium.googlesource.com/chromium/tools/depot_tools.git)

```sh
git clone https://chromium.googlesource.com/chromium/tools/depot_tools
fetch v8
gn gen out/debug --args='
is_debug = true
v8_enable_backtrace = true
v8_enable_slow_dchecks = true
v8_optimized_debug = false
'
ninja -C out/debug d8
```

## Debug d8

```sh
./d8 --allow-natives-syntax
```

### DebugPrint
```console
d8> let str = "HOGEHOGE"
undefined
d8> %DebugPrint(str)
DebugPrint: 0x38ec0006600d: [String] in OldSpace: #HOGEHOGE
0x38ec00000155: [Map] in ReadOnlySpace
 - map: 0x38ec00000475 <MetaMap (0x38ec0000002d <null>)>
 - type: INTERNALIZED_ONE_BYTE_STRING_TYPE
 - instance size: variable
 - elements kind: HOLEY_ELEMENTS
 - enum length: invalid
 - non-extensible
 - back pointer: 0x38ec00000011 <undefined>
 - prototype_validity_cell: 0
 - instance descriptors (own) #0: 0x38ec000007f1 <DescriptorArray[0]>
 - prototype: 0x38ec0000002d <null>
 - constructor: 0x38ec0000002d <null>
 - dependent code: 0x38ec000007cd <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0

"HOGEHOGE"
```

### SystemBreak()
use with debugger
```console
d8> %SystemBreak()
```

## v8 internal

### Sandbox pointer
TBD

### EPT
TBD

## Type of v8

### String

#### inheritance
```
SeqOneByteString
├── SeqString  
├── String
├── Name
├── PrimitiveHeapObject
└── HeapObject
```

#### member
| Offset | Size | Field | Source Class |
|--------|------|-------|--------------|
| 0x00 | 4 bytes | map pointer | HeapObject |
| 0x04 | 4 bytes | raw_hash_field_ | Name |
| 0x08 | 4 bytes | length_ | String |
| 0x0C+ | Variable | data_[0] | SeqOneByteString |

#### Example
```c
d8> %DebugPrint(str)
DebugPrint: 0x1b07000653e9: [String] in OldSpace: #HOGEHOGE
0x1b0700000155: [Map] in ReadOnlySpace
 - map: 0x1b0700000475 <MetaMap (0x1b070000002d <null>)>
 - type: INTERNALIZED_ONE_BYTE_STRING_TYPE
 - instance size: variable
 - elements kind: HOLEY_ELEMENTS
 - enum length: invalid
 - non-extensible
 - back pointer: 0x1b0700000011 <undefined>
 - prototype_validity_cell: 0
 - instance descriptors (own) #0: 0x1b07000007f1 <DescriptorArray[0]>
 - prototype: 0x1b070000002d <null>
 - constructor: 0x1b070000002d <null>
 - dependent code: 0x1b07000007cd <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0

"HOGEHOGE"
```

```c
gef> xxd qword 0x1b07000653e8
0x1b07000653e8:    0x36e279ea00000155 0x45474f4800000008    |  U....y.6....HOGE  |
                   |         |        |         |
                   |         |        |         └ length
                   |         |        └ data_
                   |         └ map_pointer (sandbox pointer)
                   └ hash
0x1b07000653f8:    0x0000065545474f48 0x0006540b00000002    |  HOGEU........T..  |
```

