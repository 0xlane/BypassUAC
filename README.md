# BypassUAC

利用`Autoelevated`属性的`COM`接口配合`PEB`伪装实现`BypassUAC`，分成了`C`和`C#`版本！

代码摘自：
- [UACMe](https://github.com/hfiref0x/UACME)
- [p0wnedShell](https://github.com/Cn33liz/p0wnedShell)

# 什么类型的`COM interface`可以利用？

以`UACMe`项目中索引为`41`的方法为例：
```
Author: Oddvar Moe
Type: Elevated COM interface
Method: ICMLuaUtil
Target(s): Attacker defined
Component(s): Attacker defined
Implementation: ucmCMLuaUtilShellExecMethod
Works from: Windows 7 (7600)
Fixed in: unfixed 🙈
How: -
```
该方法的目标接口是`ICMLuaUtil`，对应`Akagi`项目中具体实现函数为`ucmCMLuaUtilShellExecMethod`，在项目中的`methods/api0cradle.c`文件中可以找到该方法的定义：
![](https://raw.githubusercontent.com/cnsimo/pic_bed/master/20200418134804.png)
观察发现这里利用的是`CMSTPLUA`组件的`ICMLuaUtil`接口。

我的测试系统`Windows 10 (1909)`，使用[OleViewDotNet](https://github.com/tyranid/oleviewdotnet)工具可以查看系统中的`COM`接口属性信息，注意需要以管理员权限运行。

打开`CLSIDs`窗口搜索`cmstplua`，可以快速定位该组件：
![](https://raw.githubusercontent.com/cnsimo/pic_bed/master/20200418135050.png)
右键查看`CMSTPLUA`组件的`Elevation`属性：
![](https://raw.githubusercontent.com/cnsimo/pic_bed/master/20200418141937.png)
这里的`Enabled`和`Auto Approval`值都是`True`表示这个组件可以用来绕过`UAC`认证，这是第一点。

第二点是目标接口`ICMLuaUtil`需要有一个可以执行命令的地方，通过在`CISIDs`窗口鼠标悬浮在`ICMLuaUtil`上，可以看到该接口对应的二进制文件为`cmlua.dll`：
![](https://raw.githubusercontent.com/cnsimo/pic_bed/master/20200418144454.png)

虚函数偏移为`cmlua.dll+0x6360`，通过`IDA`打开该系统文件(`c:\windows\system32\cmlua.dll`)，跳到虚函数表的位置，可以看到`ICMLuaUtil`接口的虚函数表：
![](https://raw.githubusercontent.com/cnsimo/pic_bed/master/20200418145430.png)

摘出来看接口函数如下：
```csharp
01 QueryInterface(_GUID const &,void * *)
02 AddRef(void)
03 Release(void)
04 SetRasCredentials(ushort const *,ushort const *,ushort const *,int)
05 SetRasEntryProperties(ushort const *,ushort const *,ushort * *,ulong)
06 DeleteRasEntry(ushort const *,ushort const *)
07 LaunchInfSection(ushort const *,ushort const *,ushort const *,int)
08 LaunchInfSectionEx(ushort const *,ushort const *,ulong)
09 CreateLayerDirectory(ushort const *)
10 ShellExec(ushort const *,ushort const *,ushort const *,ulong,ulong)
11 SetRegistryStringValue(int,ushort const *,ushort const *,ushort const *)
12 DeleteRegistryStringValue(int,ushort const *,ushort const *)
13 DeleteRegKeysWithoutSubKeys(int,ushort const *,int)
14 DeleteRegTree(int,ushort const *)
15 ExitWindowsFunc(void)
16 AllowAccessToTheWorld(ushort const *)
17 CreateFileAndClose(ushort const *,ulong,ulong,ulong,ulong)
18 DeleteHiddenCmProfileFiles(ushort const *)
19 CallCustomActionDll(ushort const *,ushort const *,ushort const *,ushort const *,ulong *)
20 RunCustomActionExe(ushort const *,ushort const *,ushort * *)
21 SetRasSubEntryProperties(ushort const *,ushort const *,ulong,ushort * *,ulong)
22 DeleteRasSubEntry(ushort const *,ushort const *,ulong)
23 SetCustomAuthData(ushort const *,ushort const *,ushort const *,ulong)
```
其中第`10`个函数`ShellExec`从`IDA`中看到该函数调用了`ShellExecuteEx`这个`Windows API`实现了命令执行：
![](https://raw.githubusercontent.com/cnsimo/pic_bed/master/20200418150611.png)

通过对`ICMLuaUtil`接口的分析，可以看出可以用来`BypassUAC`执行命令的`COM`组件需要有两个特点：
1. `elevation`属性启用，且开启`Auto Approval`；
2. `COM`组件中的接口存在可以命令执行的地方，例如`ICMLuaUtil`的`ShellExec`；

# 如何快速找到系统中的所有可利用的`COM`组件？

除了通过上面的方式在`OleView`中手动去找，还可以通过`UACMe`项目提供的`Yuubari`工具快速查看系统`UAC`设定信息以及所有可以利用的程序和`COM`组件，使用方法如下：

使用`VS2019`加载`Yuubari`，生成后会得到二进制文件`UacInfo64.exe`，运行后在同目录生成一个`log`文件记录所有输出结果：
![](https://raw.githubusercontent.com/cnsimo/pic_bed/master/20200418180819.png)
从这里面可以找到所有的`Autoelevated COM objects`，包括`CMSTPLUA`组件的信息：
![](https://raw.githubusercontent.com/cnsimo/pic_bed/master/20200418182947.png)


# 定位`ICMLuaUtil`的虚函数表`vftable`

通过分析`UACMe`中的`ucmCMLuaUtilShellExecMethod`实现可以知道想要利用`COM`接口，需要知道这几个东西：
- 标识`COM`组件的`GUID`，即`CLSID`
- 标识`interface`的`GUID`，即`IID`
- 该接口的虚函数表，主要用来找到`ShellExec`的函数偏移

前两个可以很容易找到，虚函数表可以通过`OleView`提示的虚函数表位置偏移找到，这里再说一种通用的方法，完全利用`IDA`。

第一步，用`IDA`打开`cmlua.dll`；
第二步，在左侧函数列表中搜索`destructor`或者`constructor`，双击后跳转后，上下找找可以看到调用`vftable`的地方：
![](https://raw.githubusercontent.com/cnsimo/pic_bed/master/20200418153457.png)
双击跳转到变量定义位置，就可以找到虚函数表！
![](https://raw.githubusercontent.com/cnsimo/pic_bed/master/20200418145430.png)

> 参考：[Get interface definition of undocumented COM objects](https://reverseengineering.stackexchange.com/questions/19947/get-interface-definition-of-undocumented-com-objects)

# 实现部分

直接参考代码实现。