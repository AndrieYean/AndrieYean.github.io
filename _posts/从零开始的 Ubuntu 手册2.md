# 从零开始的 Ubuntu 手册 （二）

作者：laichick  
时间：2019.10.20  
纪念从一开始坚持到现在的Ubuntu  
（如果语言环境配置没有成功的话，就乖乖的用英文吧。———— 来自一位忘了装中文的菜鸡）

## 七、Ubuntu换源

### （一）“源”是什么

不准确的来说，“源”就是下载的地址。

### （二）什么时候需要“源”

安装软件程序，系统更新等等。

### （三） 为什么要换源

Ubuntu系统自带的源都是国外的网址，国内用户在使用的时候比较慢。

### （四） 换源的方法
#### 1.备份原来的源
>sudo cp /etc/apt/sources.list /etc/apt/sources_init.list

将以前的源备份一下，以防以后需要使用。

#### 2.更换阿里源
>sudo gedit /etc/apt/sources.list

使用gedit打开文档，将下边的阿里源复制进去，然后点击保存关闭。

~~~
deb http://mirrors.aliyun.com/ubuntu/ xenial main
deb-src http://mirrors.aliyun.com/ubuntu/ xenial main

deb http://mirrors.aliyun.com/ubuntu/ xenial-updates main
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates main

deb http://mirrors.aliyun.com/ubuntu/ xenial universe
deb-src http://mirrors.aliyun.com/ubuntu/ xenial universe
deb http://mirrors.aliyun.com/ubuntu/ xenial-updates universe
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates universe

deb http://mirrors.aliyun.com/ubuntu/ xenial-security main
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security main
deb http://mirrors.aliyun.com/ubuntu/ xenial-security universe
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security universe
~~~
3.更新
更新源

sudo apt-get update

修复损坏的软件包，尝试卸载出错的包，重新安装正确版本的。

sudo apt-get -f install
1
更新软件

 sudo apt-get upgrade
————————————————
版权声明：本文为CSDN博主「泉伟」的原创文章，遵循 CC 4.0 BY-SA 版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/qq_35451572/article/details/79516563