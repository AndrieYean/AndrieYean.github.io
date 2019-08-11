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

char gef[] = "source /home/andrie/.gdbinit-gef.py\0";
char pwndbg[] = "source /home/andrie/pwndbg/gdbinit.py\0";
char destfile[] = "/home/andrie/.gdbinit";
int i = -1;

void switching(char * name){
	FILE *fp;
	fp = fopen(destfile,"w");
	i += 1;
	if(strcmp(name,"gef") == 0)
		fwrite(gef,sizeof(gef) ,1,fp);
	if(strcmp(name,"pwndbg") == 0)
		fwrite(pwndbg,sizeof(pwndbg) ,1,fp);
	fclose((FILE *)fp);
}

int main(int argc,char* argv[]){
	char buf[37];
	if(argc == 1){
		FILE *fp;
		fp = fopen(destfile, "r");
		fgets(buf,37,(FILE*)fp);
		fclose((FILE *)fp);
		if(strcmp(gef,buf) == 0)
			switching("pwndbg");
		else
			switching("gef");
		return 0;
	}

	switching(argv[1]);
	
	if(i){
		puts("Argument Vector Error!");
		puts("Please try gef or pwndbg.");
	}
    
	return 0;
}
~~~
这里的buf[37]的长度是由gef[]的长度决定的。  

>gcc switchgdb.c -o switchgdb  
>sudo cp switchgdb  /bin  

这样一来，就可以愉快的切换gdb插件啦！
## EOF