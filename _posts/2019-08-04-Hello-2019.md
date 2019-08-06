---
layout:     post
title:      "Hello 2019"
subtitle:   " \"Hello World, Hello Blog\""
date:       2019-08-04 15:34:00
author:     "FitzBC"
header-img: "img/post-bg-2019.jpg"
catalog: true
tags:
    - 生活
    - Meta
---

> “Yeah It's on. ”

## 前言

Fitz 的 Blog 就这么开通了。

[跳过废话，直接看技术实现](#build)

2019 年，Fitz 总算有个地方可以好好写点东西了。

Hux大佬的一些说法很能代表一批程序猿。

>作为一个程序员， Blog 这种轮子要是挂在大众博客程序上就太没意思了。一是觉得大部分 Blog 服务都太丑，二是觉得不能随便定制不好玩。之前因为太懒没有折腾，结果就一直连个写 Blog 的地儿都没有。—— Hux

之前一直有写博客的想法，只是太懒了，一直没有去写，只是偶尔写过一篇 `CSDN` 的博客，但是界面实在是太丑了，没有继续写的欲望。今年暑假来参加 Xman 夏令营，和小智童鞋聊到了博客，我们都想开始写自己的博客，比如写写平时的 WriteUp，总结总结平时的学习成果，写写感受也挺好。

---

## Build

接下来说说搭建这个博客的技术细节。因为我是搞**漏洞复现**的，所以比较喜欢先复现，再去研究细节，所以先介绍一下如何**5分钟快速搭建**该博客。之后会补充如何细致地管理自己的博客。

### 使用Github托管博客

#### 第一分钟

Fork 仓库并修改仓库名。使用 Github 托管博客首先需要有一个 Github 账号，然后 Fork 一个自己喜欢的博客的主题，然后将 Fork 的工程名修改为 {github-username}.github.io，例如本博客 Fork 的仓库是 [https://github.com/Huxpro/huxpro.github.io](https://github.com/Huxpro/huxpro.github.io)，需要将 huxpro 修改为自己的 Github 用户名，如 `FitzBC`。

#### 第二分钟

修改配置文件。然后打开网页 fitzbc.github.com 就可以访问自己的该主题的博客了。将修改后的自己的项目 git clone 下来，按照主题说明进行配置的修改。主要需要修改的文件有 `_config.yml` 等。

#### 第三分钟

删除原博主数据。将原博主的文章及相关图片等信息删除，替换成自己的博文。博文目录为 `_posts` 目录，图片目录主要为 `img` 目录。如果有自己的域名，则可以在项目中的根目录上加 `CNAME` 文件，写上自己申请的域名，如 `www.fangzhipeng.com`。

#### 第四分钟

关闭评论功能（可选）。使用默认的评论模块是 `Disqus`，但是在国内访问速度非常慢，如果开启的话可能使得页面加载非常慢，所以如果刚开通博客暂时不需要评论功能的话可以先关闭。注释掉 `_config.yml` 文件中的 `disqus_username` 项即可。

#### 第五分钟

上传变更。git push 修改后的工程到 github 上面，github pages 就会自动构建，根据你的修改内容生成页面，访问 {github-username}.github.io 就可以看到修改后的内容。到此完成博客的快速搭建。

### 参考链接

* [掘金——程序员如何搭建自己的个人博客](https://juejin.im/post/5bcdcbc551882577e512085a)
* [Hux大佬-Build 过程](http://huangxuan.me/2015/01/29/hello-2015/)

## 后记

个人博客经历了许多坎坷今天终于搭建起来了，希望之后能够用好这个博客，多总结一些学习经历，改变一下之前的学习习惯。
