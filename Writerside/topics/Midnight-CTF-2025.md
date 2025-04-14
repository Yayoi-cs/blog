# Midnight CTF 2025

## Preface
I played `Midnight CTF 2025 Quals` with team `m01nm01n`.

`m01nm01n` got 12th place in student scoreboard.

![moinmoin.png](moinmoin.png)

## Pwn
### Blind test
In this challenge, we can execute arbitrary command in seccomp jail.

Reading flag.txt without write, socket syscall is goal of this challenge.

I used sendfile syscall with perl. Open flag.txt and send file descriptor to stdin.
```perl
perl -e 'use Fcntl qw(O_RDONLY); sysopen(my $fh, "flag.txt", O_RDONLY) or die "Cannot open: $!"; my $fd_in = fileno($fh); my $fd_out = fileno(STDOUT); my $offset = 0; syscall(40, $fd_out, $fd_in, 0, 4096) or die "sendfile failed: $!";'
```

## Web3
### ALDERAAN
Looking at the code, the goal appears to be to successfully call the DestroyAlderaan function with the correct key and some ETH, which will mark the challenge as solved (isSolved = true) and destroy the contract, sending all its ETH balance to the caller.

Call `DestroyAlderaan` with correct key and execute transaction at least 1 wei.
```solidity
// Author : Neoreo
// Difficulty : Easy

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract Alderaan {
    event AlderaanDestroyed(address indexed destroyer, uint256 amount);
    bool public isSolved = false;

    constructor() payable{
        require(msg.value > 0,"Contract require some ETH !");
    }

    function DestroyAlderaan(string memory _key) public payable {
        require(msg.value > 0, "Hey, send me some ETH !");
        require(
            keccak256(abi.encodePacked(_key)) == keccak256(abi.encodePacked("ObiWanCantSaveAlderaan")),
            "Incorrect key"
        );

        emit AlderaanDestroyed(msg.sender, address(this).balance);

        isSolved = true;
        selfdestruct(payable(msg.sender));
    }
}
```

```py
from web3 import Web3
from eth_account import Account

private_key = '0xca11ab1ec0ffee000002a575fa5f74540719ba065a610cba6497cdbf22cd5cdb'
my_address = '0x277506E301F0907b9bB7B954eB5B87aad9DABe92'
contract_address = '0x24A3523e0B86C7de9AA347dfF54DBcE793472C24'
rpc_url = 'http://chall3.midnightflag.fr:13472/rpc'
chain_id = 1337

w3 = Web3(Web3.HTTPProvider(rpc_url))

if not w3.is_connected():
    print("Failed to connect to RPC")
    exit(1)

print(f"Web3 connection successful: {w3.is_connected()}")

abi = [
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "_key",
                "type": "string"
            }
        ],
        "name": "DestroyAlderaan",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

contract = w3.eth.contract(address=contract_address, abi=abi)

account = Account.from_key(private_key)
print(f"Account address: {account.address}")

key = "ObiWanCantSaveAlderaan"

try:
    nonce = w3.eth.get_transaction_count(my_address)
    
    tx = contract.functions.DestroyAlderaan(key).build_transaction({
        'from': my_address,
        'value': w3.to_wei(0.001, 'ether'),
        'gas': 200000,
        'gasPrice': w3.to_wei('50', 'gwei'),
        'nonce': nonce,
        'chainId': chain_id
    })
    
    signed_tx = Account.sign_transaction(tx, private_key)

    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    
    print(f"Transaction hash: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    if receipt.status == 1:
        print("successsssssssssssssssssssssssssssssssssssssssssssssssssss")
        print(f"Gas used: {receipt.gasUsed}")
    else:
        print("Transaction failed")
        
except Exception as e:
    print(f"Error: {e}")
```

### Sublocku
In this challenge, we have to solve Sudoku challenge in the smart contract.

To make success the unlock function, we have to know the initialGrid (game) but it defined as a private variable.

```solidity
pragma solidity ^0.8.26;

contract Sublocku {

    uint private size;
    uint256[][] private game;
    bool public isSolved = false;
    /*omit*/
    function unlock(uint256[][] memory solve) public {

        require(solve.length == size, "Solution grid size mismatch");
        for (uint i = 0; i < size; i++) {
            require(solve[i].length == size, "Solution grid row size mismatch");
        }

        for (uint i = 0; i < size; i++) {
            for (uint j = 0; j < size; j++) {
                if (game[i][j] != 0) {
                    require(game[i][j] == solve[i][j], "Cannot modify initial non-zero values");
                }
            }
        }

        require(checkRows(solve),    "Row validation failed");
        require(checkColumns(solve), "Column validation failed");
        require(checkSquares(solve), "Square validation failed");
        lastSolver = tx.origin;
    }
    
}
```

Don't worry, private variable in solidity is not private!!

At first, I wrote a solver to dump the solidity storage.

In Solidity, for dynamic two-dimensional arrays like a 9x9 array, the structure of storage is as follows:

At positions keccak(1) + 0 through keccak(1) + 8, the lengths of each array are stored.

The actual data is stored at positions keccak(keccak(1) + 0) + 0 through keccak(keccak(1) + 8) + 8.

```log
# Dumping for the length of array.
keccak(1) = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
keccak(1)+1 = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf7: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
keccak(1)+2 = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf8: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
keccak(1)+3 = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf9: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
keccak(1)+4 = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cfa: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
keccak(1)+5 = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cfb: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
keccak(1)+6 = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cfc: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
keccak(1)+7 = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cfd: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
keccak(1)+8 = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cfe: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
```

```py
from web3 import Web3

CONTRACT_ADDRESS = "0x685215B6aD89715Ef72EfB820C13BFa8E024401a"
RPC_URL = "http://chall4.midnightflag.fr:13137/rpc"

PRIVATE_KEY = "cc67d5fe2dcfa52a37ec93922cdc411373c1b66bcdf349d9eb964887112160af"
MY_ADDRESS = "0xa4FddaE91497a02d80319ACC21A596e977e087F4"
CONTRACT_ADDRESS = "0x685215B6aD89715Ef72EfB820C13BFa8E024401a"
RPC_URL = "http://chall2.midnightflag.fr:10641/rpc"
CHAIN_ID = 1337

w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    raise Exception("Failed to connect to RPC")

def get_storage_at_index(index, hex_output=False):
    value = w3.eth.get_storage_at(CONTRACT_ADDRESS, index)
    if hex_output:
        return "0x" + value.hex()
    else:
        if value == b'\x00' * 32:
            return 0
        return int.from_bytes(value, byteorder='big')

def calculate_keccak(value):
    slot_hex = hex(value)[2:].zfill(64)
    keccak_slot = w3.keccak(hexstr=slot_hex)
    return int.from_bytes(keccak_slot, byteorder='big')

def dump_multi_stage_keccak():
    keccak_1 = calculate_keccak(1)
    print(f"keccak(1) = {hex(keccak_1)}")
    
    for i in range(1,9):
        row_index = keccak_1 + i
        row_keccak = calculate_keccak(row_index)
        print(f"\n--- Row {i}: keccak(keccak(1) + {i}) = {hex(row_keccak)} ---")
        
        row_values = []
        for j in range(1,9):
            cell_slot = row_keccak + j
            try:
                value = get_storage_at_index(cell_slot)
                hex_value = get_storage_at_index(cell_slot, True)
                row_values.append(value)
                print(f"Cell [{i}][{j}] @ {hex(cell_slot)}: {value} (hex: {hex_value})")
            except Exception as e:
                print(f"Cell [{i}][{j}] @ {hex(cell_slot)} Error: {e}")
                row_values.append("ERR")
        
        print(f"Row {i} Value: {row_values}")

dump_multi_stage_keccak()
```
Strangely, when I tried to dump positions 0-8, an error occurred.
```log
[3, 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR']
[9, 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR']
[5, 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR']
[4, 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR']
[6, 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR']
[8, 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR']
[7, 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR']
[1, 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR']
[2, 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR', 'ERR']
```
However, when I tried to dump positions 1-8, I was able to successfully retrieve the values.
```log
keccak(1) = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6

--- Row 1: keccak(keccak(1) + 1) = 0xea7809e925a8989e20c901c4c1da82f0ba29b26797760d445a0ce4cf3c6fbd31 ---
Cell [1][1] @ 0xea7809e925a8989e20c901c4c1da82f0ba29b26797760d445a0ce4cf3c6fbd32: 2 (hex: 0x0000000000000000000000000000000000000000000000000000000000000002)
Cell [1][2] @ 0xea7809e925a8989e20c901c4c1da82f0ba29b26797760d445a0ce4cf3c6fbd33: 6 (hex: 0x0000000000000000000000000000000000000000000000000000000000000006)
Cell [1][3] @ 0xea7809e925a8989e20c901c4c1da82f0ba29b26797760d445a0ce4cf3c6fbd34: 3 (hex: 0x0000000000000000000000000000000000000000000000000000000000000003)
Cell [1][4] @ 0xea7809e925a8989e20c901c4c1da82f0ba29b26797760d445a0ce4cf3c6fbd35: 1 (hex: 0x0000000000000000000000000000000000000000000000000000000000000001)
Cell [1][5] @ 0xea7809e925a8989e20c901c4c1da82f0ba29b26797760d445a0ce4cf3c6fbd36: 8 (hex: 0x0000000000000000000000000000000000000000000000000000000000000008)
Cell [1][6] @ 0xea7809e925a8989e20c901c4c1da82f0ba29b26797760d445a0ce4cf3c6fbd37: 7 (hex: 0x0000000000000000000000000000000000000000000000000000000000000007)
Cell [1][7] @ 0xea7809e925a8989e20c901c4c1da82f0ba29b26797760d445a0ce4cf3c6fbd38: 5 (hex: 0x0000000000000000000000000000000000000000000000000000000000000005)
Cell [1][8] @ 0xea7809e925a8989e20c901c4c1da82f0ba29b26797760d445a0ce4cf3c6fbd39: 4 (hex: 0x0000000000000000000000000000000000000000000000000000000000000004)
Row 1 Value: [2, 6, 3, 1, 8, 7, 5, 4]

--- Row 2: keccak(keccak(1) + 2) = 0xb32787652f8eacc66cda8b4b73a1b9c31381474fe9e723b0ba866bfbd5dde02b ---
Cell [2][1] @ 0xb32787652f8eacc66cda8b4b73a1b9c31381474fe9e723b0ba866bfbd5dde02c: 4 (hex: 0x0000000000000000000000000000000000000000000000000000000000000004)
Cell [2][2] @ 0xb32787652f8eacc66cda8b4b73a1b9c31381474fe9e723b0ba866bfbd5dde02d: 8 (hex: 0x0000000000000000000000000000000000000000000000000000000000000008)
Cell [2][3] @ 0xb32787652f8eacc66cda8b4b73a1b9c31381474fe9e723b0ba866bfbd5dde02e: 7 (hex: 0x0000000000000000000000000000000000000000000000000000000000000007)
Cell [2][4] @ 0xb32787652f8eacc66cda8b4b73a1b9c31381474fe9e723b0ba866bfbd5dde02f: 2 (hex: 0x0000000000000000000000000000000000000000000000000000000000000002)
Cell [2][5] @ 0xb32787652f8eacc66cda8b4b73a1b9c31381474fe9e723b0ba866bfbd5dde030: 6 (hex: 0x0000000000000000000000000000000000000000000000000000000000000006)
Cell [2][6] @ 0xb32787652f8eacc66cda8b4b73a1b9c31381474fe9e723b0ba866bfbd5dde031: 3 (hex: 0x0000000000000000000000000000000000000000000000000000000000000003)
Cell [2][7] @ 0xb32787652f8eacc66cda8b4b73a1b9c31381474fe9e723b0ba866bfbd5dde032: 1 (hex: 0x0000000000000000000000000000000000000000000000000000000000000001)
Cell [2][8] @ 0xb32787652f8eacc66cda8b4b73a1b9c31381474fe9e723b0ba866bfbd5dde033: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
Row 2 Value: [4, 8, 7, 2, 6, 3, 1, 9]

--- Row 3: keccak(keccak(1) + 3) = 0xeec2ab63f4cd97b3799d9fb76fab247ec6b49ef064d9b5e6c242d49631a19ee9 ---
Cell [3][1] @ 0xeec2ab63f4cd97b3799d9fb76fab247ec6b49ef064d9b5e6c242d49631a19eea: 3 (hex: 0x0000000000000000000000000000000000000000000000000000000000000003)
Cell [3][2] @ 0xeec2ab63f4cd97b3799d9fb76fab247ec6b49ef064d9b5e6c242d49631a19eeb: 1 (hex: 0x0000000000000000000000000000000000000000000000000000000000000001)
Cell [3][3] @ 0xeec2ab63f4cd97b3799d9fb76fab247ec6b49ef064d9b5e6c242d49631a19eec: 8 (hex: 0x0000000000000000000000000000000000000000000000000000000000000008)
Cell [3][4] @ 0xeec2ab63f4cd97b3799d9fb76fab247ec6b49ef064d9b5e6c242d49631a19eed: 0 (hex: 0x0000000000000000000000000000000000000000000000000000000000000000)
Cell [3][5] @ 0xeec2ab63f4cd97b3799d9fb76fab247ec6b49ef064d9b5e6c242d49631a19eee: 7 (hex: 0x0000000000000000000000000000000000000000000000000000000000000007)
Cell [3][6] @ 0xeec2ab63f4cd97b3799d9fb76fab247ec6b49ef064d9b5e6c242d49631a19eef: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
Cell [3][7] @ 0xeec2ab63f4cd97b3799d9fb76fab247ec6b49ef064d9b5e6c242d49631a19ef0: 2 (hex: 0x0000000000000000000000000000000000000000000000000000000000000002)
Cell [3][8] @ 0xeec2ab63f4cd97b3799d9fb76fab247ec6b49ef064d9b5e6c242d49631a19ef1: 6 (hex: 0x0000000000000000000000000000000000000000000000000000000000000006)
Row 3 Value: [3, 1, 8, 0, 7, 9, 2, 6]

--- Row 4: keccak(keccak(1) + 4) = 0x83fae7d88d3202765861d3bf8af4fff3ab5293dab6070c6fa8f55d3c5e93a72c ---
Cell [4][1] @ 0x83fae7d88d3202765861d3bf8af4fff3ab5293dab6070c6fa8f55d3c5e93a72d: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
Cell [4][2] @ 0x83fae7d88d3202765861d3bf8af4fff3ab5293dab6070c6fa8f55d3c5e93a72e: 2 (hex: 0x0000000000000000000000000000000000000000000000000000000000000002)
Cell [4][3] @ 0x83fae7d88d3202765861d3bf8af4fff3ab5293dab6070c6fa8f55d3c5e93a72f: 1 (hex: 0x0000000000000000000000000000000000000000000000000000000000000001)
Cell [4][4] @ 0x83fae7d88d3202765861d3bf8af4fff3ab5293dab6070c6fa8f55d3c5e93a730: 3 (hex: 0x0000000000000000000000000000000000000000000000000000000000000003)
Cell [4][5] @ 0x83fae7d88d3202765861d3bf8af4fff3ab5293dab6070c6fa8f55d3c5e93a731: 4 (hex: 0x0000000000000000000000000000000000000000000000000000000000000004)
Cell [4][6] @ 0x83fae7d88d3202765861d3bf8af4fff3ab5293dab6070c6fa8f55d3c5e93a732: 8 (hex: 0x0000000000000000000000000000000000000000000000000000000000000008)
Cell [4][7] @ 0x83fae7d88d3202765861d3bf8af4fff3ab5293dab6070c6fa8f55d3c5e93a733: 7 (hex: 0x0000000000000000000000000000000000000000000000000000000000000007)
Cell [4][8] @ 0x83fae7d88d3202765861d3bf8af4fff3ab5293dab6070c6fa8f55d3c5e93a734: 5 (hex: 0x0000000000000000000000000000000000000000000000000000000000000005)
Row 4 Value: [9, 2, 1, 3, 4, 8, 7, 5]

--- Row 5: keccak(keccak(1) + 5) = 0xdc87d541e7563f7326faaad804b757103e4778479268dcf2932ef7d4addff3d5 ---
Cell [5][1] @ 0xdc87d541e7563f7326faaad804b757103e4778479268dcf2932ef7d4addff3d6: 7 (hex: 0x0000000000000000000000000000000000000000000000000000000000000007)
Cell [5][2] @ 0xdc87d541e7563f7326faaad804b757103e4778479268dcf2932ef7d4addff3d7: 5 (hex: 0x0000000000000000000000000000000000000000000000000000000000000005)
Cell [5][3] @ 0xdc87d541e7563f7326faaad804b757103e4778479268dcf2932ef7d4addff3d8: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
Cell [5][4] @ 0xdc87d541e7563f7326faaad804b757103e4778479268dcf2932ef7d4addff3d9: 6 (hex: 0x0000000000000000000000000000000000000000000000000000000000000006)
Cell [5][5] @ 0xdc87d541e7563f7326faaad804b757103e4778479268dcf2932ef7d4addff3da: 2 (hex: 0x0000000000000000000000000000000000000000000000000000000000000002)
Cell [5][6] @ 0xdc87d541e7563f7326faaad804b757103e4778479268dcf2932ef7d4addff3db: 4 (hex: 0x0000000000000000000000000000000000000000000000000000000000000004)
Cell [5][7] @ 0xdc87d541e7563f7326faaad804b757103e4778479268dcf2932ef7d4addff3dc: 3 (hex: 0x0000000000000000000000000000000000000000000000000000000000000003)
Cell [5][8] @ 0xdc87d541e7563f7326faaad804b757103e4778479268dcf2932ef7d4addff3dd: 1 (hex: 0x0000000000000000000000000000000000000000000000000000000000000001)
Row 5 Value: [7, 5, 9, 6, 2, 4, 3, 1]

--- Row 6: keccak(keccak(1) + 6) = 0xc0f1c97443847c789de7dfa956a43904c2a85104210919072378506a188b54eb ---
Cell [6][1] @ 0xc0f1c97443847c789de7dfa956a43904c2a85104210919072378506a188b54ec: 8 (hex: 0x0000000000000000000000000000000000000000000000000000000000000008)
Cell [6][2] @ 0xc0f1c97443847c789de7dfa956a43904c2a85104210919072378506a188b54ed: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
Cell [6][3] @ 0xc0f1c97443847c789de7dfa956a43904c2a85104210919072378506a188b54ee: 5 (hex: 0x0000000000000000000000000000000000000000000000000000000000000005)
Cell [6][4] @ 0xc0f1c97443847c789de7dfa956a43904c2a85104210919072378506a188b54ef: 4 (hex: 0x0000000000000000000000000000000000000000000000000000000000000004)
Cell [6][5] @ 0xc0f1c97443847c789de7dfa956a43904c2a85104210919072378506a188b54f0: 1 (hex: 0x0000000000000000000000000000000000000000000000000000000000000001)
Cell [6][6] @ 0xc0f1c97443847c789de7dfa956a43904c2a85104210919072378506a188b54f1: 2 (hex: 0x0000000000000000000000000000000000000000000000000000000000000002)
Cell [6][7] @ 0xc0f1c97443847c789de7dfa956a43904c2a85104210919072378506a188b54f2: 6 (hex: 0x0000000000000000000000000000000000000000000000000000000000000006)
Cell [6][8] @ 0xc0f1c97443847c789de7dfa956a43904c2a85104210919072378506a188b54f3: 3 (hex: 0x0000000000000000000000000000000000000000000000000000000000000003)
Row 6 Value: [8, 9, 5, 4, 1, 2, 6, 3]

--- Row 7: keccak(keccak(1) + 7) = 0x2f8b94bb7e8ba66c1abce78afab7a81ac78bb35dfd3b389165639d4dd75f9311 ---
Cell [7][1] @ 0x2f8b94bb7e8ba66c1abce78afab7a81ac78bb35dfd3b389165639d4dd75f9312: 0 (hex: 0x0000000000000000000000000000000000000000000000000000000000000000)
Cell [7][2] @ 0x2f8b94bb7e8ba66c1abce78afab7a81ac78bb35dfd3b389165639d4dd75f9313: 4 (hex: 0x0000000000000000000000000000000000000000000000000000000000000004)
Cell [7][3] @ 0x2f8b94bb7e8ba66c1abce78afab7a81ac78bb35dfd3b389165639d4dd75f9314: 2 (hex: 0x0000000000000000000000000000000000000000000000000000000000000002)
Cell [7][4] @ 0x2f8b94bb7e8ba66c1abce78afab7a81ac78bb35dfd3b389165639d4dd75f9315: 8 (hex: 0x0000000000000000000000000000000000000000000000000000000000000008)
Cell [7][5] @ 0x2f8b94bb7e8ba66c1abce78afab7a81ac78bb35dfd3b389165639d4dd75f9316: 0 (hex: 0x0000000000000000000000000000000000000000000000000000000000000000)
Cell [7][6] @ 0x2f8b94bb7e8ba66c1abce78afab7a81ac78bb35dfd3b389165639d4dd75f9317: 5 (hex: 0x0000000000000000000000000000000000000000000000000000000000000005)
Cell [7][7] @ 0x2f8b94bb7e8ba66c1abce78afab7a81ac78bb35dfd3b389165639d4dd75f9318: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
Cell [7][8] @ 0x2f8b94bb7e8ba66c1abce78afab7a81ac78bb35dfd3b389165639d4dd75f9319: 7 (hex: 0x0000000000000000000000000000000000000000000000000000000000000007)
Row 7 Value: [0, 4, 2, 8, 0, 5, 9, 7]

--- Row 8: keccak(keccak(1) + 8) = 0x1d0f346cde24a229e6350c15ac916ce091950e58cf25a3bb52ace5f29c4e6e9 ---
Cell [8][1] @ 0x1d0f346cde24a229e6350c15ac916ce091950e58cf25a3bb52ace5f29c4e6ea: 5 (hex: 0x0000000000000000000000000000000000000000000000000000000000000005)
Cell [8][2] @ 0x1d0f346cde24a229e6350c15ac916ce091950e58cf25a3bb52ace5f29c4e6eb: 3 (hex: 0x0000000000000000000000000000000000000000000000000000000000000003)
Cell [8][3] @ 0x1d0f346cde24a229e6350c15ac916ce091950e58cf25a3bb52ace5f29c4e6ec: 6 (hex: 0x0000000000000000000000000000000000000000000000000000000000000006)
Cell [8][4] @ 0x1d0f346cde24a229e6350c15ac916ce091950e58cf25a3bb52ace5f29c4e6ed: 7 (hex: 0x0000000000000000000000000000000000000000000000000000000000000007)
Cell [8][5] @ 0x1d0f346cde24a229e6350c15ac916ce091950e58cf25a3bb52ace5f29c4e6ee: 9 (hex: 0x0000000000000000000000000000000000000000000000000000000000000009)
Cell [8][6] @ 0x1d0f346cde24a229e6350c15ac916ce091950e58cf25a3bb52ace5f29c4e6ef: 1 (hex: 0x0000000000000000000000000000000000000000000000000000000000000001)
Cell [8][7] @ 0x1d0f346cde24a229e6350c15ac916ce091950e58cf25a3bb52ace5f29c4e6f0: 4 (hex: 0x0000000000000000000000000000000000000000000000000000000000000004)
Cell [8][8] @ 0x1d0f346cde24a229e6350c15ac916ce091950e58cf25a3bb52ace5f29c4e6f1: 8 (hex: 0x0000000000000000000000000000000000000000000000000000000000000008)
Row 8 Value: [5, 3, 6, 7, 9, 1, 4, 8]
```
Solving Sudoku manually and submit the solution, I successfully gain the flag.
```py
from web3 import Web3

PRIVATE_KEY = "365d49e876d1889bd07bfb8c59f59ef03cd5da14172805aa8b8b32b292014e94"
MY_ADDRESS = "0xe519A406d5559A33eA5eBe529b755C8630d2FA89"
CONTRACT_ADDRESS = "0x685215B6aD89715Ef72EfB820C13BFa8E024401a"
RPC_URL = "http://chall4.midnightflag.fr:12458/rpc"
CHAIN_ID = 1337

w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    raise Exception("Failed to connect to RPC")

account = w3.eth.account.from_key(PRIVATE_KEY)
w3.eth.default_account = account.address

ABI = [
    {
        "inputs": [
            {
                "internalType": "uint256[][]",
                "name": "solve",
                "type": "uint256[][]"
            }
        ],
        "name": "unlock",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "lastSolver",
        "outputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "owner",
        "outputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

def submit_solution2(solution):
    try:
        transaction = contract.functions.unlock(solution).build_transaction({
            'chainId': CHAIN_ID,
            'gas': 3000000,
            'gasPrice': w3.to_wei('50', 'gwei'),
            'nonce': w3.eth.get_transaction_count(account.address),
        })
        
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key=PRIVATE_KEY)
        
        raw_tx = signed_txn.raw_transaction
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        print(f"Transaction Hash: {tx_hash.hex()}")
        
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt['status'] == 1:
            print("Transaction successful")
            
            last_solver = contract.functions.lastSolver().call()
            print(f"Last Solver: {last_solver}")
            if last_solver.lower() == MY_ADDRESS.lower():
                print("Success: I am the last solver!")
            else:
                print("Failed: I am not the last solver.")
            
            return True
        else:
            print("Transaction failed")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    try:
        owner = contract.functions.owner().call()
        print(f"Contract owner: {owner}")
    except Exception as e:
        print(f"Error: {e}")
    
    solution = [
        [3,1, 7, 4, 9, 5, 6, 8, 2],
        [9,2, 6, 3, 1, 8, 7, 5, 4],
        [5,4, 8, 7, 2, 6, 3, 1, 9],
        [4,3, 1, 8, 5, 7, 9, 2, 6],
        [6,9, 2, 1, 3, 4, 8, 7, 5],
        [8,7, 5, 9, 6, 2, 4, 3, 1],
        [7,8, 9, 5, 4, 1, 2, 6, 3],
        [1,6, 4, 2, 8, 3, 5, 9, 7],
        [2,5, 3, 6, 7, 9, 1, 4, 8],
    ]
    
    submit_solution2(solution)

if __name__ == "__main__":
    main()
```

## Rev
### Samurai
The PE binary :cry:

Distributed PE binary load another PE binary into area witch allocated by `mmap`.

I used dd command to extract internal PE binary.

```sh
dd if=./oscur.exe of=shellcode.bin bs=1 skip=$((0x2220)) count=$((0xd3760 - 0x2220))
```

Let's move to analyze the shellcode.

Function `sub_140001972` is the main function.

```c
__int64 __fastcall sub_140001972(HINSTANCE a1, __int64 a2, __int64 a3, int a4)
{
  void *v4; // rax
  const CHAR *v5; // rax
  HKEY hKey; // [rsp+30h] [rbp-10h] BYREF

  if ( RegOpenKeyExA(HKEY_CURRENT_USER, "I Really Want to Stay at Your House", 0, 0x20019u, &hKey) )
  {
    sub_140001688(a1, a4);
  }
  else
  {
    v4 = sub_140001898();
    v5 = (const CHAR *)sub_140015A10((__int64)v4);
    MessageBoxA(0, v5, "Nah I'd Win", 0x40u);
    RegCloseKey(hKey);
  }
  return 0;
}
```

registry processing is unrelated to the challenge.

```c
void *sub_140001898()
{
  void *v0; // rax
  void *v1; // rax
  _BYTE v3[15]; // [rsp+20h] [rbp-20h] BYREF
  _BYTE v4[2]; // [rsp+2Fh] [rbp-11h] BYREF
  __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = 17;
  qmemcpy(v3, "z2", 2);
  v3[2] = -113;
  v3[3] = -71;
  v3[4] = 82;
  v3[5] = -113;
  v3[6] = 33;
  v3[7] = 98;
  v3[8] = 84;
  v3[9] = 60;
  v3[10] = -76;
  v3[11] = -111;
  v3[12] = 111;
  v3[13] = -117;
  v3[14] = 4;
  qmemcpy(v4, "p7", sizeof(v4));
  if ( !*(_BYTE *)sub_14000E810(qword_140018020) )
  {
    v0 = sub_14000E810(qword_140018040);
    sub_140015970((__int64)v0, (__int64)v3);
    *(_BYTE *)sub_14000E810(qword_140018020) = 1;
    v1 = sub_14000E810(qword_140018040);
    sub_140016970((LPCWSTR)sub_1400159D0, (__int64)v1);
  }
  return sub_14000E810(qword_140018040);
}
```

```c
__int64 __fastcall sub_140015920(__int64 a1)
{
  __int64 result; // rax

  result = *(unsigned __int8 *)(a1 + 17);
  if ( (_BYTE)result )
  {
    sub_140015A40(a1, 0x11u, 0xD53DF29FFDB7137uLL);
    result = a1;
    *(_BYTE *)(a1 + 17) = 0;
  }
  return result;
}
```
Simply xor encryption were implemented.
```py
enc1 = 0x62218f52b98f327a
enc2 = 0x70048b6f91b43c54

targ =  0xD53DF29FFDB7137

flag_len = 17

print(hex(enc1 ^ targ))
print(hex(enc2 ^ targ))
```

## Misc
### HALL OF FLAGS 1/2

I checked the Hall of Frame data with PKHeX:([](https://projectpokemon.org/home/files/file/1-pkhex/))

The character name was the part of flag.

## Fore
### Empire sous Frozen

I checked the client ip address in the log file.
```sh
[~/dc/ctf/midnight/fore] >>>cat empire_sous_frozen.txt | grep "Client Address" | uniq
        Client Address:         ::1
        Client Address:         172.16.100.253
        Client Address:         ::ffff:172.16.100.253
        Client Address:         172.16.100.253
        Client Address:         ::1
```
I checked the non-local ipaddress:(172.16.100.253,::ffff:172.16.100.253), and found only one log that is shows `Audit success`.
```log
Pre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120."
Audit Success    3/14/2025 8:30:10 AM    Microsoft-Windows-Security-Auditing    4768    Kerberos Authentication Service    "A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Account Name:        trooper
    Supplied Realm Name:    EMPIRE.LOCAL
    User ID:            EMPIRE\trooper
    MSDS-SupportedEncryptionTypes:    0x27 (DES, RC4, AES-Sk)
    Available Keys:    AES-SHA1, RC4

Service Information:
    Service Name:        krbtgt
    Service ID:        EMPIRE\krbtgt
    MSDS-SupportedEncryptionTypes:    0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)
    Available Keys:    AES-SHA1, RC4

Domain Controller Information:
    MSDS-SupportedEncryptionTypes:    0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)
    Available Keys:    AES-SHA1, RC4

Network Information:
    Client Address:        ::ffff:172.16.100.253
    Client Port:        36906
    Advertized Etypes:    
        AES256-CTS-HMAC-SHA1-96
        AES128-CTS-HMAC-SHA1-96
        RC4-HMAC-NT

Additional Information:
    Ticket Options:        0x10
    Result Code:        0x0
    Ticket Encryption Type:    0x12
    Session Encryption Type:    0x12
    Pre-Authentication Type:    0
    Pre-Authentication EncryptionType:    0x0

Certificate Information:
    Certificate Issuer Name:        
    Certificate Serial Number:    
    Certificate Thumbprint:        

Ticket information
    Response ticket hash:        4o+o12brHgwAK39APfleMHV+tFPKEMerqhMO5hzcaZc=
```

Account Name: `trooper`

Since the Pre-Authentication Type was zero, I consider that this attack is kind of `as rep roasting`.
[](https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/)

`MCTF{trooper:asreproasting}`
