---
layout:     post
title:      "Web-渗透小结"
subtitle:   " \"Web-渗透小结(一)\""
date:       2019-08-04 20:21:00
author:     "FitzBC"
header-img: "img/post-bg-2019.jpg"
catalog: true
tags:
    - Web
    - 渗透
---

> “Yeah It's on. ”

## 前言

听了一天吴一雄师傅的 Web 课，想要总结一下相关内容。

---

## Web 渗透实战技巧

### 危险函数

什么样的函数导致什么样的漏洞

* 文件包含->包含漏洞
* 代码执行->执行任意代码漏洞
* 命令执行->执行任意命令漏洞
* 文件系统操作->文件（目录）读写等漏洞
* 数据库操作->SQL 注入
* 数据显示->XSS等客户端/服务端漏洞

### 漏洞挖掘思路（白盒）

1. 根据敏感关键字回溯参数传递过程
    * 主要针对一些高危函数、关键字附近。发现可控变量后，追踪变量传递过程查询是否有可利用的地方。
2. 查找可控变量，正向追踪变量传递过程
3. 查找敏感功能点，通读功能点代码
   * 敏感功能点：文件上传位置、admin 页面、数据库操作页面
4. 直接通读全文代码
   * 阅读全文时，关注一些 common 文件、共享库文件、配置文件、index 文件、安全过滤文件

### 开发能力

* 要成为一个优秀的渗透攻城狮，必须是一个合格的开发攻城狮
* 了解Web运行框架，知识面广
* 好奇心，关注细节，关注**不一致性**

### 信息收集

* 第三方内容：广告统计、muckup
* Web前端框架：jQuery/Bootstrap/HTML5框架
* Web应用：BBS/CMS/BLOG
* Web开发框架：Django/Rails/Thinkphp
* Web服务端语言：PHP/JSP/.NET
* Web容器：Apache/IIS/Nginx
* 存储：数据库存储/内存存储/文件存储
* 操作系统：Linux/Windows

## Web 渗透测试工具

### 渗透测试工具

* Chrome
  * F12
    * Elements
    * Console
    * Sources
    * Network（抓包）
    * Application（）
      * 该面板主要是记录网站加载的所有资源信息
      * **修改 Cookies 可直接在这里修改**
  * Extensions
    * Proxy SwitchyOmega
      * 快速切各种代理
    * EditThisCookie
      * 编辑、删除、添加、创建、搜索cookies
    * ModHeader
      * 修改 HTTP 头
    * HackBar (Firefox)
* BurpSuite
  * Extensions
  * Proxy
  * Repeater
  * Decoder
  * Intruder
  * Extender
  * User options
  * Extender
    * [Reissue Request Scripter 6.0]
      * [https://github.com/PortSwigger/reissuerequest-scripter](https://github.com/PortSwigger/reissue-request-scripter)
* AntSward
  * [https://github.com/AntSwordProject/antSword](https://github.com/AntSwordProject/antSword)
* PHP
  * PHPStudy – windows
  * MAMP Pro – OSX
  * LNMP - Linux
* SQLmap
  * [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
* Encode/Decode
  * LEAVESONG工具架
    * [http://tool.leavesongs.com/](http://tool.leavesongs.com/)
  * cmd5（反查MD5）
    * [https://www.cmd5.com/](https://www.cmd5.com/)
  * somd5（反查MD5）
    * [https://www.somd5.com](https://www.cmd5.com/)
  * CSP Evaluator（审计CSP的）
    * [https://csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com)
  * Generate a Content-Security-Policy header（在线生成 CSP 头）
    * [https://www.cspisawesome.com/](https://www.cspisawesome.com/)
  * XSS'OR（）
    * [http://xssor.io/#ende](http://xssor.io/#ende)
* Regex
  * 正则表达式30分钟入门教程
    * [http://deerchao.net/tutorials/regex/regex.htm](http://deerchao.net/tutorials/regex/regex.htm)
  * regex101
    * [https://regex101.com/](https://regex101.com/)
  * regexper
    * [https://regexper.com](https://regexper.com)
* Snack
  * 搜索引擎
    * [https://thief.one/2017/05/19/1/](https://thief.one/2017/05/19/1/)
  * 字符集
    * [http://collation-charts.org/](http://collation-charts.org/)
  * 在线工具 - 程序员的工具箱
    * [https://tool.lu](https://tool.lu)

### 代码审计工具

* 1.基本环境
  * Windows:
    * PHPStudy
  * MAC
    * MAMP PRO
  * Linux
    * LNMP
* 2.代码阅读器
  * Sublime
  * VS Code
  * VIM...
* 3.代码调试器
  * PHPStorm
* 4.自动化审计工具
  * 1.Seay源代码审计工具
  * 2.Cobra工具
  * 3.Fortify SCA
  * 4.RIPS
