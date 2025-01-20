# uiuctf2024

## Crypt
### X Marked the Spot
Easy,XOR Encryption.

Challenge
```python
from itertools import cycle

flag = b"uiuctf{????????????????????????????????????????}"
# len(flag) = 48
key  = b"????????"
# len(key) = 8
ct = bytes(x ^ y for x, y in zip(flag, cycle(key)))

with open("ct", "wb") as ct_file:
    ct_file.write(ct)
```
Solver
```python
from itertools import cycle

with open("ct","rb") as ctfile:
    ct = ctfile.read()

#known = b"uiuctf{"
#uiuctf{~0t_ju5tOth3_st4bt_but_4|50_th3_#nd!!!!!m
known = b"uiuctf{n"

#segment = ct[:7]
segment = ct[:8]

key = bytes(x ^ y for x,y in zip(segment,known))

print(f"key : {key}")
keys = key # + b"a" 

flag = bytes(x^y for x,y in zip(ct,cycle(keys)))

print(f"flag : {flag.decode()}")
#key : b'hdiqbfjq'
#flag : uiuctf{n0t_ju5t_th3_st4rt_but_4l50_th3_3nd!!!!!}
```
### Without the Trace

$$
F=
\begin{bmatrix}
Segment1 & 0 & 0 & 0 & 0\\
0 & Segment2 & 0 & 0 & 0\\
0 & 0 & Segment3 & 0 & 0\\
0 & 0 & 0 & Segment4 & 0\\
0 & 0 & 0 & 0 & Segment5
\end{bmatrix}
$$

$$
M=
\begin{bmatrix}
input1 & 0 & 0 & 0 & 0\\
0 & input2 & 0 & 0 & 0\\
0 & 0 & input3 & 0 & 0\\
0 & 0 & 0 & input4 & 0\\
0 & 0 & 0 & 0 & input5
\end{bmatrix}
$$

$$ np.trace(R) = Segment1*input1 + Segment2*input2 + Segment3*input3 ... $$

Solver
```python
from Crypto.Util.number import long_to_bytes
#input 1,1,1,1,1
daemon = 2000128101369
u = [
    2504408575853 - daemon, #input 2,1,1,1,1
    2440285994541 - daemon, #input 1,2,1,1,1
    2426159182680 - daemon, #input 1,1,2,1,1
    2163980646766 - daemon, #input 1,1,1,2,1
    2465934208374 - daemon   #input 1,1,1,1,2
]
for i in u:
    print(long_to_bytes(i).decode(),end="")

print("")
#uiuctf{tr4c1ng_&&_mult5!}
```

### Determined

$$
M=
\begin{bmatrix}
p & 0 & input & 0 & input\\
0 & input & 0 & input & 0\\
input & 0 & input & 0 & input\\
0 & q & 0 & r & 0\\
input & 0 & input & 0 & 0
\end{bmatrix}
$$

Add log print
```python
def fun(M):
    def sign(sigma):
        l = 0
        for i in range(5):
            for j in range(i + 1, 5):
                if sigma[i] > sigma[j]:
                    l += 1
        return (-1)**l

    res = 0
    for sigma in permutations([0,1,2,3,4]):
        curr = 1
        for i in range(5):
            #print(f"M :: {M[sigma[i]][i]}")
            curr *= M[sigma[i]][i]
        #print(f"CURR :: {curr}")
        if curr != 0:
            print(f"SIGMA :: {sigma}\n\tCURR :: {curr}")
        res += sign(sigma) * curr
    return res
```
p=5,q=7,r=3 in this time.
```bash
$python3 server.py 
[DET] Welcome
[DET] First things first, gimme some numbers:
[DET] M[0][2] = 1
[DET] M[0][4] = 1
[DET] M[1][1] = 1
[DET] M[1][3] = 1
[DET] M[2][0] = 1
[DET] M[2][2] = 1
[DET] M[2][4] = 1
[DET] M[4][0] = 1
[DET] M[4][2] = 1
SIGMA :: (0, 1, 4, 3, 2)
        CURR :: 15
SIGMA :: (0, 3, 4, 1, 2)
        CURR :: 35
SIGMA :: (2, 1, 4, 3, 0)
        CURR :: 3
SIGMA :: (2, 3, 4, 1, 0)
        CURR :: 7
SIGMA :: (4, 1, 0, 3, 2)
        CURR :: 3
SIGMA :: (4, 1, 2, 3, 0)
        CURR :: 3
SIGMA :: (4, 3, 0, 1, 2)
        CURR :: 7
SIGMA :: (4, 3, 2, 1, 0)
        CURR :: 7
[DET] Have fun: 16
```
Found r when SIGMA = (2, 1, 4, 3, 0) and pr when SIGMA = (0, 1, 4, 3, 2)
```bash
$ncat --ssl determined.chal.uiuc.tf 1337
[DET] Welcome
[DET] First things first, gimme some numbers:
[DET] M[0][2] = 0    
[DET] M[0][4] = 1
[DET] M[1][1] = 1
[DET] M[1][3] = 0
[DET] M[2][0] = 1
[DET] M[2][2] = 0
[DET] M[2][4] = 0
[DET] M[4][0] = 0
[DET] M[4][2] = 1
[DET] Have fun: 7079077828991557904453386075761691430024858841559152638771101891403817504002722603786046116429444882212741713778792076162641378721868400698674834419068143
```
$$ r = 7079077828991557904453386075761691430024858841559152638771101891403817504002722603786046116429444882212741713778792076162641378721868400698674834419068143 $$
```bash
$ncat --ssl determined.chal.uiuc.tf 1337
[DET] Welcome
[DET] First things first, gimme some numbers:
[DET] M[0][2] = 0
[DET] M[0][4] = 0
[DET] M[1][1] = 1
[DET] M[1][3] = 0
[DET] M[2][0] = 0
[DET] M[2][2] = 0
[DET] M[2][4] = 1
[DET] M[4][0] = 0
[DET] M[4][2] = 1
[DET] Have fun: -89650932835934569650904059412290773134844226367466628096799329748763412779644167490959554682308225788447301887591344484909099249454270292467079075688237075940004535625835151778597652605934044472146068875065970359555553547536636518184486497958414801304532202276337011187961205104209096129018950458239166991017
```
$$ pr = 89650932835934569650904059412290773134844226367466628096799329748763412779644167490959554682308225788447301887591344484909099249454270292467079075688237075940004535625835151778597652605934044472146068875065970359555553547536636518184486497958414801304532202276337011187961205104209096129018950458239166991017 $$

$$ p = 12664210650260034332394963174199526364356188908394557935639380180146845030597260557316300143360207302285226422265688727606524707066404145712652679087174119 $$

By the gen.txt
$$ n = 158794636700752922781275926476194117856757725604680390949164778150869764326023702391967976086363365534718230514141547968577753309521188288428236024251993839560087229636799779157903650823700424848036276986652311165197569877428810358366358203174595667453056843209344115949077094799081260298678936223331932826351 $$

$$ q =  12538849920148192679761652092105069246209474199128389797086660026385076472391166777813291228233723977872612370392782047693930516418386543325438897742835129 $$

Solver
```python
from Crypto.Util.number import inverse,long_to_bytes

p = 12664210650260034332394963174199526364356188908394557935639380180146845030597260557316300143360207302285226422265688727606524707066404145712652679087174119
q = 12538849920148192679761652092105069246209474199128389797086660026385076472391166777813291228233723977872612370392782047693930516418386543325438897742835129
e = 65535
c = 72186625991702159773441286864850566837138114624570350089877959520356759693054091827950124758916323653021925443200239303328819702117245200182521971965172749321771266746783797202515535351816124885833031875091162736190721470393029924557370228547165074694258453101355875242872797209141366404264775972151904835111

n = p * q

phi_n = (p - 1) * (q - 1)

d = inverse(e, phi_n)

m = pow(c, d, n)

print(long_to_bytes(m).decode())
#uiuctf{h4rd_w0rk_&&_d3t3rm1n4t10n}
```

## OSINT
### Chunky Boi
I found a flight data.
https://ads-b.nl/aircraft.php?id_aircraft=11411651&selectmove=day&movedate=2024-05-11

![image](https://hackmd.io/_uploads/ryX0ahyvR.png)

uiuctf{Boeing C-17 Globemaster III, 47.462, -122.303}

## Web
### Fare Evasion
![image](https://hackmd.io/_uploads/rkP60h1wC.png)

Cookie : access_token
```plain text
eyJhbGciOiJIUzI1NiIsImtpZCI6InBhc3Nlbmdlcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoicGFzc2VuZ2VyIn0.EqwTzKXS85U_CbNznSxBz8qA1mDZOs1JomTXSbsw0Zs
```
https://github.com/gen0cide/hasherbasher

![image](https://hackmd.io/_uploads/HkkMl6JwR.png)

```plain text
eyJhbGciOiJIUzI1NiIsImtpZCI6IkR5cmhHT1lQMHZ4STJEdEg4eSIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiY29uZHVjdG9yIn0.jFCtw7Xi4WzujhfDRjLMez-qEfm-al8sVpvc00Dfr4k
```

![image](https://hackmd.io/_uploads/ryGngakPC.png)


![image](https://hackmd.io/_uploads/BJBHTp1PA.png)

```plain text
eyJhbGciOiJIUzI1NiIsImtpZCI6ImNvbmR1Y3Rvcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoiY29uZHVjdG9yIn0.9YEcZgwQH46F4wckPyovNOwao49zdlEPoQ9HdiXimK4
```

![image](https://hackmd.io/_uploads/HJat66ywR.png)
