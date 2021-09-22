科锐三阶段项目---PE程序调试器

程序流程设置命令
1.	单步步入
命令：t
参数：无
说明：设置单步步入，程序会运行一条指令并断下，如果遇到CALL指令，会断在CALL到的地址处。

2.	单步步过
命令：p
参数：无
说明：设置单步步过，如果遇到的不是CALL指令，程序会运行一条指令并断下；如果遇到CALL指令，会断在CALL指令后的下一条指令处，即CALL内部的指令已经执行完。

3.	运行
命令：g
参数：地址 或 无
说明：让被调试程序直接运行，或运行到参数所指定的地址处。
示例：g 4001008，指定被调试程序运行到4001008地址处断下。

查看信息命令
1.	反汇编代码
命令：u
参数：地址 或 无
说明：反汇编出八条被调试程序的汇编指令，参数如果没有指定则从EIP指向的地址向后依次反汇编，参数如果指定则从指定地址处开始进行反汇编。
示例：u 00401017，从00401017地址处反汇编八条汇编指令。
00401017 C1E002               SHL EAX, 02
0040101A A31F014B00           MOV DWORD PTR DS:[004B011F], EAX
0040101F 52                   PUSH EDX
00401020 6A00                 PUSH 00
00401022 E84BE00A00           CALL 004AF072 <jmp.kernel32.GetModuleHandleA>
00401027 8BD0                 MOV EDX, EAX
00401029 E8DA240A00           CALL 004A3508
0040102E 5A                   POP EDX
0040102F E870180A00           CALL 004A28A4
00401034 E8D3240A00           CALL 004A350C
2.	查看内存数据
命令：dd
参数：地址 或 无
说明：从参数指定的地址处显示128个内存字节，如果参数没有指定，则从上一次显示数据的地址处往后继续显示数据。
示例：D 004013A0，从004013A0地址处显示128个字节的数据。8行
004017D0  55 8B EC 6A FF 68 80 71-42 00 68 00 5C 40 00 64   U..j.h.qB.h.\@.d
004017E0  A1 00 00 00 00 50 64 89-25 00 00 00 00 83 C4 F0   .....Pd.%.......
004017F0  53 56 57 89 65 E8 FF 15-7C F1 42 00 A3 E4 CE 42   SVW.e...|.B....B
00401800  00 A1 E4 CE 42 00 C1 E8-08 25 FF 00 00 00 A3 F0   ....B....%......
00401810  CE 42 00 8B 0D E4 CE 42-00 81 E1 FF 00 00 00 89   .B.....B........
00401820  0D EC CE 42 00 8B 15 EC-CE 42 00 C1 E2 08 03 15   ...B.....B......
00401830  F0 CE 42 00 89 15 E8 CE-42 00 A1 E4 CE 42 00 C1   ..B.....B....B..
00401840  E8 10 25 FF FF 00 00 A3-E4 CE 42 00 6A 00 E8 2D   ..%.......B.j..-
3.	查看寄存器指令
命令：r
参数：地址 或 无
说明：显示寄存器组中各寄存器的值。
示例：r
EAX =00000000  EBX =7FFDB000  ECX =0012FFB0  EDX =7C92E514  ESI =00000000
EDI =00000000  ESP =0012FFC4  EBP =0012FFF0  FS  =0000003B
CS  =0000001B  DS  =00000023  ES  =00000023  SS  =00000023  EIP =004017D0
CF:0 PF:1 AF:0 ZF:1 SF:0 TF:0 IF:1 DF:0 OF:0
四、	一般断点
1.	设置一般断点
命令：bp
参数：地址
说明：在参数地址指定处下一般断点。
示例：bp 4001023

2.	查看一般断点列表
命令：bpl
参数：无
说明：显示所有的一般断点。
示例：bpl
---------------------一般断点列表---------------------
序号  地址       代码    类型
0     00401000   CC      用户断点
1     00402000   FF      用户断点
------------------------------------------------------
3.	删除一般断点
命令：bpc
参数：一般断点的ID序号
说明：删除参数所指定序号的一般断点。
示例：bpc 1

硬件断点
1.	设置硬件断点
命令：bh
参数一：断点地址
参数二：断点类型。访问、写入、执行三者之一。
参数三：断点长度(可为1,2,4中的一个)。
说明：设置一个由参数所指定的硬件断点。
示例：bh 0400321A e(硬件断点如果是执行类型，可不指定断点长度)
      bh 0400321A a 2
      bh 0400321A w 4

2.	查看硬件断点列表
命令：bhl
参数：无
说明：显示所有的硬件断点。
示例：bpl
---------------------硬件断点列表---------------------
序号       断点地址
0          00401000
1          00402000
2          00403000
------------------------------------------------------
3.	删除硬件断点
命令：bhc
参数：断点序号
说明：删除参数序号所指定的硬件断点。
示例：bhc 1

内存断点
1.	设置内存断点
命令：bm
参数一：断点地址
参数二：长度
参数三：断点类型。读、写入二者之一
说明：设置一个由参数所指定的内存断点。
示例：bm 0400321A  2 w
      bm 0400321A  4 r

2.	查看内存断点列表
命令：bml
参数：无
说明：显示所有的内存断点。
示例：bml
---------------------内存断点列表---------------------
序号  地址       长度   类型
1     00401000   2      写
2     00402000   3      读
------------------------------------------------------
命令：bmpl
参数：无
说明：显示分页的内存断点。
---------------------分页断点列表---------------------
分页地址   断点标号   旧属性     新属性
00401000   1          00000020   00000001
00402000   2          00000020   00000001
------------------------------------------------------
3.	删除内存断点
命令：bmc
参数：断点序号
说明：删除参数（序号）所指定的内存断点。
示例：bmc 2

脚本功能
1.	导入脚本
命令：ls
参数：无
说明：导入一个脚本文件（后缀名为SCP）。会逐行解析脚本文件的命令，并执行该命令。

2.	导出脚本
命令：es
参数：无
说明：将用户操作的所有有效命令导出到一个脚本文件。
3.	自动跟踪
命令：trace
参数1:开始跟踪的起始地址
参数2:停止跟踪的结束地址
参数3:指定需要跟踪的模块
说明：
trace 00401230 00401560 Test.exe
00401230-00401560的地址范围内所有
记录过的地址不用重复记录
