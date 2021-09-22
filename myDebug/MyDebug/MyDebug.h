#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <list>
#include <vector>
#include <conio.h>
#include <string.h>

#include "Decode2Asm.h"
#include "Disasm.h"

#include "MyErrorReport.h"

using namespace std;

#define CMD_SIZE        10
#define MODULE_SIZE     50
#define TRACE_SIZE      100
#define TF_FALG         0x100


union  DR7
{
    struct
    {
        unsigned int L0 : 1;
        unsigned int G0 : 1;
        unsigned int L1 : 1;
        unsigned int G1 : 1;
        unsigned int L2 : 1;
        unsigned int G2 : 1;
        unsigned int L3 : 1;
        unsigned int G3 : 1;
        unsigned int LE : 1;
        unsigned int GE : 1;
        unsigned int : 1;
        unsigned int RTM : 1;
        unsigned int : 1;
        unsigned int GD : 1;
        unsigned int : 2;
        unsigned int RW0 : 2;
        unsigned int LEN0 : 2;
        unsigned int RW1 : 2;
        unsigned int LEN1 : 2;
        unsigned int RW2 : 2;
        unsigned int LEN2 : 2;
        unsigned int RW3 : 2;
        unsigned int LEN3 : 2;
    };
    unsigned int dr7;
};

union  EFLAG
{
    struct  
    {
        unsigned int CF : 1;
        unsigned int : 1;
        unsigned int PF : 1;
        unsigned int : 1;
        unsigned int AF : 1;
        unsigned int : 1;
        unsigned int ZF : 1;
        unsigned int SF : 1;
        unsigned int TF : 1;
        unsigned int IF : 1;
        unsigned int DF : 1;
        unsigned int OF : 1;
        unsigned int : 24;
    };
    unsigned nEflag = 0;
};

struct DEBUGORDER
{
    char   szCMD[CMD_SIZE] = { 0 };        //命令
    char   szModule[MODULE_SIZE] = { 0 };  //模块名
    void*  pAddrBegin = 0;                 //开始地址
    void*  pAddrEnd = 0;                   //结束地址
    char   cType = 0;                      //类型
    union 
    {
        int    nNum;                       //序号
        int    nBpLenth;                   //断点长度
        bool   bOnce;                      //是否一次断点
    }Other;
    
};

struct BREAKPOINT//此结构为所有断点公用，所以会出现某些断点不需要的成员
{
    void*  pAddr = nullptr;            //地址
    bool   isOnce = false;             //是否是一次断点
    int    nSize = 0;                  //断点尺寸
    char   cType = 0;                  //断点类型
    DWORD  dwOldType = 0;              //之前的内存保护属性
    union 
    {
        unsigned char cOld;          //断点以前的值
        void*  nPage;                //断点分页
        int  nDRNum = 0;             //标记当前是哪一个硬件断点寄存器的值
    }Other;
};

struct TRACEINFO
{
    int nAddr = 0;                     //跟踪的地址
    char szTrace[TRACE_SIZE] = { 0 };  //跟踪的信息
};

class MyDebug
{
public:
    MyDebug();
    ~MyDebug();

    void Run();

private:
    //调试事件函数
    DWORD ExceptionDebugEvent();
    DWORD CreateThreadDebugEvnet();
    DWORD CreateProcessDebugEvnet();
    DWORD ExitThreadDebugEvnet();
    DWORD ExitProcessDebugEvnet();
    DWORD LoadDllDebugEvnet();
    DWORD UnloadDllDebugEvnet();
    DWORD OutputStringDebugEvnet();
    DWORD RipDebugEvnet();

    bool  GetScriptInfo(DEBUGORDER* dbOrder);     //获取一条脚本信息
    void  GetUserInput(DEBUGORDER* dbOrder);      //获取用户输入
    DWORD GetCommand();                           //获取指令并处理
    char* GetDebugFilePath();                     //获取调试文件路径
    void  SavaOrder(DEBUGORDER* pOrder);          //保存正确的指令到链表
    void  SavaDebugState();                       //保存调试状态,将指令链表写进文件，考虑一下调用时机

    DWORD ExceptionBreakPoint();                  //断点异常
    DWORD ExceptionAccess();                      //访问异常
    DWORD ExceptionSingleStep();                  //单步异常

    void*  ShowDisassembler(void* addr, int line); //显示反汇编
    void   ShowRegister();                         //显示寄存器信息
    void   ShowModule();                           //显示模块
    void*  ShowMemoryData(void* pAddr);            //显示内存数据
    void   ShowNormalBreakPoint();                 //显示一般断点列表
    void   ShowHardBreakPoint();                   //显示硬件断点列表
    void   ShowMemoryBreakPoint();                 //显示内存断点列表
    void   ShowPageBreakPoint();                   //显示分页断点列表

    DWORD MyReadProcessMomory(DWORD pid, void* addr, unsigned char* buffer, DWORD len);  //读进程内存
    DWORD MyWriteProcessMomory(DWORD pid, void* addr, unsigned char* buffer, DWORD len); //写进程内存
    
    DWORD MyGetContext(DWORD tid, CONTEXT& context); //获取线程环境
    DWORD MySetContext(DWORD tid, CONTEXT& context); //设置线程环境

    bool JudgeIsCall(DWORD pIpAddr);                                //判断参数IP的地址是否是call指令,如果是，则在下一条指令下一次性断点
    void CmdSetStepInto();                                          //设置单步步入标志  
    void CmdSetStepOver();                                          //设置单步步过标志  
    bool CmdSetBreakPoint(void* addr, bool isOnce);                 //设置普通断点
    bool CmdSetHardBreakPoint(void* addr, char cType, int nSize);   //设置硬件断点
    bool CmdSetMemoryBreakPoint(void* addr, char cType, int nSize); //设置内存断点
    bool CmdSetGoBreakPoint(void* addr);                            //设置go指令

    BREAKPOINT* GetBreakPointInfo();                    //从断点链表获取断点信息
    int FindHardBreakPoint();                           //判断当前异常IP是否是处在硬件断点,是则返回断点数，否则返回-1

    bool GetMoDuleRange(char* szModule);                //获取模块的起始地址范围
    void SetTraceInfo(int nAddr, char* pTrace);         //设置跟踪信息
    void GetTraceInfo(char* pTrace);                    //获取跟踪信息，写文件

    void  ExportScript();                                //导出脚本
    void  ImportScript();                                //导入脚本
    void* EditMemoryData(void* pAddr);                   //修改内存数据
    bool  DeleteNormalBreakPoint(int nNum);              //删除一般断点
    bool  DeleteHardBreakPoint(int nNum);                //删除硬件断点
    bool  DeleteMemoryBreakPoint(int nNum);              //删除内存断点
    void  FreeList();                                    //释放所有链表

public:
    char* m_pDebugFilePath = nullptr;             //被调试程序的路径
    DEBUG_EVENT m_DebugEv;                        //调试事件的信息 
    DWORD m_dwContinueStatus = DBG_CONTINUE;      //异常处理状态
    STARTUPINFO m_si = { 0 };
    PROCESS_INFORMATION m_pi = { 0 };
    FILE* m_pFile = NULL;
    void* m_pTeb = NULL;
    BREAKPOINT* m_pCurrentBreakPoint = nullptr;  //当前操作的断点
    void*  m_pShowMemory = nullptr;              //显示的内存地址
    void*  m_pEditMemoryData = nullptr;          //修改内存数据的地址
    void*  m_pMemoryExceptionAddr = nullptr;     //发生内存异常的地址

public:
    int  m_nTraceBegin = 0;              //跟踪记录的起点
    int  m_nTraceEnd = 0Xffffffff;       //跟踪记录的终点
    int  m_nModuleBegin = 0;             //跟踪的模块起点
    int  m_nModuleEnd = 0Xffffffff;      //跟踪的模块终点
    int  m_nProcBegin = 0;               //程序的模块入口
    int  m_nProcEnd = 0;                 //程序的模块结尾；
    int  m_nHardBreakPointNum = 0;       //硬件断点个数
    int  m_nGoAddr = 0;                  //go指令的地址
    unsigned char m_cGoCode = 0;                  //go指令地址的原代码

public:
    bool m_bIsExecuteCode = false;       //是否执行过用户代码
    bool m_bTrace = false;               //是否开启跟踪
    bool m_bTraceBegin = false;          //是否进入跟踪区域
    bool m_bTraceModule = false;         //是否有跟踪的模块
    bool m_bExecuteRecordFile = false;   //当前是否要先执行脚本文件的指令
    bool m_bIsSystem = true;             //是否是系统断点
    bool m_bIsNormalBreakPoint = false;  //是否是一般断点
    bool m_bIsMemoryBreakPoint = false;  //是否是内存断点
    bool m_bIsHardBreakPoint = false;    //是否是硬件断点
    bool m_bIsMemoryException = false;   //是否引发过内存异常
    bool m_bIsExit = false;              //是否退出调试

public:
    list<TRACEINFO*> m_lstTrace;              //跟踪信息的链表，信息在ShowDisassembler中被加入到链表，每次加入之前1先看当前地址是否在模块地址范围 2.遍历链表的地址，如果相同就不添加，最后关进程的时候写文件
    list<DEBUGORDER*> m_lstExecuteOrder;      //执行过的指令
    list<BREAKPOINT*> m_lstNormalBreakPoint;  //一般断点
    list<BREAKPOINT*> m_lstMemoryBreakPoint;  //内存断点
    list<BREAKPOINT*> m_lstHardBreakPoint;    //硬件断点
    
};
