# Closers-CMF-TOOLS
CMF PAK/UNPACK ，Supports CMF versions V1 to V10，Break through file size limitations and support replacement of X/PNG/DDS/OGG

《封印者》最新CMF封包解包工具[2026.6.29]，由MagicalKing（B站ID：不可思议的MagicalKing）与CJM(B站ID：゚恶意)联合制作。

软件功能：支持CMF V1到V10封包解包，已经突破文件大小限制，支持常用文件X/PNG/DDS/OGG 等替换。

本程序已完全开源，目前提供的是v1.1版，打开是命令行窗口界面，使用数字输入进行操作，功能齐全，过几天将更新GUI版，后续源码和编译后的工具会同步更新至github。

# [2026.7.2]v1.1更新说明

修复程序读取部分CMF时因识别不出带韩文名称的资源文件而导致报错Debug Error! (abort() has been called) 的问题。

# 程序使用介绍：

bak目录：在封包前会拷贝原CMF目录下所有*.cmf文件到bak目录，用于备份，因为封包后cmf目录下的*.cmf会被自动替换成封包后的文件。

cmf目录：在封包解包时，要事先将客户端中的指定cmf文件放进这个目录中，封包与解包都会读取这个目录。

pak目录：在封包时，会将pak目录下的所有素材文件重新封装到cmf目录里。

unpack目录：在解包时，会将cmf目录下的所有*.cmf文件全部解包到unpack目录中

还要说明一点，以上四个目录只针对单文件目录封包与解包，在进行客户端全解包时不会用到这些目录。

# config.ini配置文件：

game_path=F:\NetGame\CLOSERS

output_dir=E:\OUT

game_path对应的是你的封印者游戏客户端路径

output_dir对应的是你解包客户端后的路径

# 重要说明：

使用本工具封包后，程序会对CMF进行完整重建，重建后的大小会跟封包前的cmf不一样，如果要放进游戏客户端使其生效，就需要提前修改HEADER.CMF。

HEADER.CMF位于游戏客户端DAT目录下，这个文件用于检测并效验游戏文件是否一致，如果检测到大小不一致，启动器就会自动从服务器上下载原文件替换更改后的文件。

# 过文件效验：

首先一定要备份HEADER.CMF，建议压缩打包，或者将HEADER.CMF改名为HEADER1.CMF，再新建一个带后缀的文本文档，改名为HEADER.CMF.

打开空字节的HEADER.CMF的属性，依次打开-[安全]-[高级]-[禁用继承]-[从此对象删除所有已继承的权限]，最后[确定]退出。

打开启动器，直接开始游戏，启动器会因为检测不到HEADER.CMF而延迟10~15秒左右才进入游戏，但后面进游戏就很快了，在游戏里查看替换后的cmf效果吧！

之所以为什么需要备份原HEADER.CMF，是因为若遇到游戏更新的情况，需要将HEADER.CMF还原成正常文件，才能更新，否则游戏更新会一直卡住。

# 免责声明：

本工具仅仅是学习研究用途，请勿恶意滥用，若您使用本工具对游戏平衡造成了极其不利的影响，导致账号被封禁，程序作者一概不负责。


# C++源文件(main.cpp)说明

本源文件用VS2026生成，并在安装了vcpkg和64位zlib依赖库的情况下编译通过。具体怎样安装vcpkg和zlib，请用搜索引擎查阅。

以下是项目配置：

Windows SDK版本：Windows10.0 SDK(最新)

平台工具集：v145 for Microsoft C++ Build Tools

C++语言标准：ISO C++ 20标准(/std:c++20)
