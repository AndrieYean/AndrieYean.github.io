# How to patch the format strings

## Approach One : Replace 'printf' with 'puts'

As is known to all, this way is easy but effective.

### 0x1  Calculate the relative offset

Find the current address  ( address of the next instruction )  
```
.text:0804889F                 call    printf
.text:080488A4                 add     esp, 10h
```  
After the call_printf is 0x80488A4  
  
Find the puts_plt address   

Calculate the offset:

>offset = puts_plt - call_next_addr

### 0x2  Convert the offset to complement when necessary  

>print hex(0xffffffff-offset+1)  

### 0x3  Change byte  

>Edit –> Patch Program –> Change Byte     

Change the 8 bytes after E8 (call)  

Dont't fotget it's little-endian.  
  
### 0x4 Save  

>Edit –> Patch Program –> Apply patches to input file  


# EOF