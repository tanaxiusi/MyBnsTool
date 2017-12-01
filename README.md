# MyBnsTool
网游『剑灵』dat文件修改器，支持64位

算法参考自bnsdat项目https://sourceforge.net/projects/bns-tools/files/bnsdat/

增加64位支持，并优化执行速度。

用法与bnsdat基本相同：

    -e/-x <输入文件> <输出目录>        解包dat文件，使用"-x"会同时转换xml文件成可读格式。
                                       输出目录可以不指定，默认值为"<输入目录>.files"

    -c <输入目录> <输出文件>           打包dat文件。如果<输入目录>以".files"结尾，输出文件可以不指定。

    -s <xml文件>                       转换xml文件格式。

    -e64/-x64/-c64                     -e/-x/-c的64位版本。


# 如何编译

上面有编译好并加壳压缩的exe文件，如果想自己编译可以看下去。

我的编译环境是VS2015+Qt5.9.0，理论上支持c++11的都可以，Qt4应该也行。

aes加密算法用到了openssl(https://github.com/openssl/openssl) 考虑到这个项目比较大，就不放上来了，编译完放到项目OpenSSL目录下即可。

然后就是Qt常规编译流程，切换到项目目录，qmake，nmake(或make)。
