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
    char   szCMD[CMD_SIZE] = { 0 };        //����
    char   szModule[MODULE_SIZE] = { 0 };  //ģ����
    void*  pAddrBegin = 0;                 //��ʼ��ַ
    void*  pAddrEnd = 0;                   //������ַ
    char   cType = 0;                      //����
    union 
    {
        int    nNum;                       //���
        int    nBpLenth;                   //�ϵ㳤��
        bool   bOnce;                      //�Ƿ�һ�ζϵ�
    }Other;
    
};

struct BREAKPOINT//�˽ṹΪ���жϵ㹫�ã����Ի����ĳЩ�ϵ㲻��Ҫ�ĳ�Ա
{
    void*  pAddr = nullptr;            //��ַ
    bool   isOnce = false;             //�Ƿ���һ�ζϵ�
    int    nSize = 0;                  //�ϵ�ߴ�
    char   cType = 0;                  //�ϵ�����
    DWORD  dwOldType = 0;              //֮ǰ���ڴ汣������
    union 
    {
        unsigned char cOld;          //�ϵ���ǰ��ֵ
        void*  nPage;                //�ϵ��ҳ
        int  nDRNum = 0;             //��ǵ�ǰ����һ��Ӳ���ϵ�Ĵ�����ֵ
    }Other;
};

struct TRACEINFO
{
    int nAddr = 0;                     //���ٵĵ�ַ
    char szTrace[TRACE_SIZE] = { 0 };  //���ٵ���Ϣ
};

class MyDebug
{
public:
    MyDebug();
    ~MyDebug();

    void Run();

private:
    //�����¼�����
    DWORD ExceptionDebugEvent();
    DWORD CreateThreadDebugEvnet();
    DWORD CreateProcessDebugEvnet();
    DWORD ExitThreadDebugEvnet();
    DWORD ExitProcessDebugEvnet();
    DWORD LoadDllDebugEvnet();
    DWORD UnloadDllDebugEvnet();
    DWORD OutputStringDebugEvnet();
    DWORD RipDebugEvnet();

    bool  GetScriptInfo(DEBUGORDER* dbOrder);     //��ȡһ���ű���Ϣ
    void  GetUserInput(DEBUGORDER* dbOrder);      //��ȡ�û�����
    DWORD GetCommand();                           //��ȡָ�����
    char* GetDebugFilePath();                     //��ȡ�����ļ�·��
    void  SavaOrder(DEBUGORDER* pOrder);          //������ȷ��ָ�����
    void  SavaDebugState();                       //�������״̬,��ָ������д���ļ�������һ�µ���ʱ��

    DWORD ExceptionBreakPoint();                  //�ϵ��쳣
    DWORD ExceptionAccess();                      //�����쳣
    DWORD ExceptionSingleStep();                  //�����쳣

    void*  ShowDisassembler(void* addr, int line); //��ʾ�����
    void   ShowRegister();                         //��ʾ�Ĵ�����Ϣ
    void   ShowModule();                           //��ʾģ��
    void*  ShowMemoryData(void* pAddr);            //��ʾ�ڴ�����
    void   ShowNormalBreakPoint();                 //��ʾһ��ϵ��б�
    void   ShowHardBreakPoint();                   //��ʾӲ���ϵ��б�
    void   ShowMemoryBreakPoint();                 //��ʾ�ڴ�ϵ��б�
    void   ShowPageBreakPoint();                   //��ʾ��ҳ�ϵ��б�

    DWORD MyReadProcessMomory(DWORD pid, void* addr, unsigned char* buffer, DWORD len);  //�������ڴ�
    DWORD MyWriteProcessMomory(DWORD pid, void* addr, unsigned char* buffer, DWORD len); //д�����ڴ�
    
    DWORD MyGetContext(DWORD tid, CONTEXT& context); //��ȡ�̻߳���
    DWORD MySetContext(DWORD tid, CONTEXT& context); //�����̻߳���

    bool JudgeIsCall(DWORD pIpAddr);                                //�жϲ���IP�ĵ�ַ�Ƿ���callָ��,����ǣ�������һ��ָ����һ���Զϵ�
    void CmdSetStepInto();                                          //���õ��������־  
    void CmdSetStepOver();                                          //���õ���������־  
    bool CmdSetBreakPoint(void* addr, bool isOnce);                 //������ͨ�ϵ�
    bool CmdSetHardBreakPoint(void* addr, char cType, int nSize);   //����Ӳ���ϵ�
    bool CmdSetMemoryBreakPoint(void* addr, char cType, int nSize); //�����ڴ�ϵ�
    bool CmdSetGoBreakPoint(void* addr);                            //����goָ��

    BREAKPOINT* GetBreakPointInfo();                    //�Ӷϵ������ȡ�ϵ���Ϣ
    int FindHardBreakPoint();                           //�жϵ�ǰ�쳣IP�Ƿ��Ǵ���Ӳ���ϵ�,���򷵻ضϵ��������򷵻�-1

    bool GetMoDuleRange(char* szModule);                //��ȡģ�����ʼ��ַ��Χ
    void SetTraceInfo(int nAddr, char* pTrace);         //���ø�����Ϣ
    void GetTraceInfo(char* pTrace);                    //��ȡ������Ϣ��д�ļ�

    void  ExportScript();                                //�����ű�
    void  ImportScript();                                //����ű�
    void* EditMemoryData(void* pAddr);                   //�޸��ڴ�����
    bool  DeleteNormalBreakPoint(int nNum);              //ɾ��һ��ϵ�
    bool  DeleteHardBreakPoint(int nNum);                //ɾ��Ӳ���ϵ�
    bool  DeleteMemoryBreakPoint(int nNum);              //ɾ���ڴ�ϵ�
    void  FreeList();                                    //�ͷ���������

public:
    char* m_pDebugFilePath = nullptr;             //�����Գ����·��
    DEBUG_EVENT m_DebugEv;                        //�����¼�����Ϣ 
    DWORD m_dwContinueStatus = DBG_CONTINUE;      //�쳣����״̬
    STARTUPINFO m_si = { 0 };
    PROCESS_INFORMATION m_pi = { 0 };
    FILE* m_pFile = NULL;
    void* m_pTeb = NULL;
    BREAKPOINT* m_pCurrentBreakPoint = nullptr;  //��ǰ�����Ķϵ�
    void*  m_pShowMemory = nullptr;              //��ʾ���ڴ��ַ
    void*  m_pEditMemoryData = nullptr;          //�޸��ڴ����ݵĵ�ַ
    void*  m_pMemoryExceptionAddr = nullptr;     //�����ڴ��쳣�ĵ�ַ

public:
    int  m_nTraceBegin = 0;              //���ټ�¼�����
    int  m_nTraceEnd = 0Xffffffff;       //���ټ�¼���յ�
    int  m_nModuleBegin = 0;             //���ٵ�ģ�����
    int  m_nModuleEnd = 0Xffffffff;      //���ٵ�ģ���յ�
    int  m_nProcBegin = 0;               //�����ģ�����
    int  m_nProcEnd = 0;                 //�����ģ���β��
    int  m_nHardBreakPointNum = 0;       //Ӳ���ϵ����
    int  m_nGoAddr = 0;                  //goָ��ĵ�ַ
    unsigned char m_cGoCode = 0;                  //goָ���ַ��ԭ����

public:
    bool m_bIsExecuteCode = false;       //�Ƿ�ִ�й��û�����
    bool m_bTrace = false;               //�Ƿ�������
    bool m_bTraceBegin = false;          //�Ƿ�����������
    bool m_bTraceModule = false;         //�Ƿ��и��ٵ�ģ��
    bool m_bExecuteRecordFile = false;   //��ǰ�Ƿ�Ҫ��ִ�нű��ļ���ָ��
    bool m_bIsSystem = true;             //�Ƿ���ϵͳ�ϵ�
    bool m_bIsNormalBreakPoint = false;  //�Ƿ���һ��ϵ�
    bool m_bIsMemoryBreakPoint = false;  //�Ƿ����ڴ�ϵ�
    bool m_bIsHardBreakPoint = false;    //�Ƿ���Ӳ���ϵ�
    bool m_bIsMemoryException = false;   //�Ƿ��������ڴ��쳣
    bool m_bIsExit = false;              //�Ƿ��˳�����

public:
    list<TRACEINFO*> m_lstTrace;              //������Ϣ��������Ϣ��ShowDisassembler�б����뵽����ÿ�μ���֮ǰ1�ȿ���ǰ��ַ�Ƿ���ģ���ַ��Χ 2.��������ĵ�ַ�������ͬ�Ͳ���ӣ����ؽ��̵�ʱ��д�ļ�
    list<DEBUGORDER*> m_lstExecuteOrder;      //ִ�й���ָ��
    list<BREAKPOINT*> m_lstNormalBreakPoint;  //һ��ϵ�
    list<BREAKPOINT*> m_lstMemoryBreakPoint;  //�ڴ�ϵ�
    list<BREAKPOINT*> m_lstHardBreakPoint;    //Ӳ���ϵ�
    
};
