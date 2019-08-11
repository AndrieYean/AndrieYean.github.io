# gef与pwndbg的快速切换  
为了不需要手动写入文件切换gef与pwndgb，今天自己写了一个小小程序。  
![scratch-head](..\..\..\..\pics\emojis\scratch-head.jpg)  
方法有非常多：

>alias修改指令  
使用shell脚本  
......  
  
这里我选择用C语言写一个可执行文件放到/bin里面当做指令使用。  
这应该是最简单的方法之一吧。  
  
gdb插件的初始化文件是 .gdbinit文件:  
>pwndbg: source ~/pwndbg/gdbinit.py  
gef: source ~/.gdbinit-gef.py  
peda: source ~/peda/peda.py  
  
因为pwndbg和peda比较相似，所以我就把peda删除辽。  

本菜鸡的源码如下(我的胆子已经这么肥了嘛)：

~~~c
#include <stdio.h>
#include <string.h>
int main(int argc,char* argv[]){
	
	char buf[37];
	char gef[] = "source /home/andrie/.gdbinit-gef.py\0";
	char pwndbg[] = "source /home/andrie/pwndbg/gdbinit.py\0";
	
	if(argc == 1){
		FILE *fp;
		fp = fopen("/home/andrie/.gdbinit", "r");
		fgets(buf,37,(FILE*)fp);

		if(strcmp(gef,buf) != 0){
			fclose((FILE *)fp);
			FILE *fp2;
			fp2 = fopen("/home/andrie/.gdbinit", "w");
			fwrite(gef,sizeof(gef) ,1,fp2);
			fclose((FILE *)fp2);
		}

		else{
			fclose((FILE *)fp);
			FILE *fp2;
			fp2 = fopen("/home/andrie/.gdbinit", "w");
			fwrite(pwndbg,sizeof(pwndbg) ,1,fp2);
			fclose((FILE *)fp2);
		}
		return 0;
	}

	if(strcmp(argv[1],"gef") == 0){
			FILE *fp;
			fp = fopen("/home/andrie/.gdbinit", "w");
			fwrite(gef,sizeof(gef) ,1,fp);
			fclose((FILE *)fp);
			return 0;
		}

	if(strcmp(argv[1],"pwndbg") == 0){
			FILE *fp;
			fp = fopen("/home/andrie/.gdbinit", "w");
			fwrite(pwndbg,sizeof(pwndbg) ,1,fp);
			fclose((FILE *)fp);
			return 0;
		}

	puts("Argument Vector Error!");
	puts("Please try gef or pwndbg.");
	return 0;
}
~~~
这里的buf[37]的长度是由gef[]的长度决定的。  

>gcc switchgdb.c -o switchgdb  
>sudo cp switchgdb  /bin  

这样一来，就可以愉快的切换gdb插件啦！
## EOF