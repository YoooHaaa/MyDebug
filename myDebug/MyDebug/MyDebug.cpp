#include "MyDebug.h"



MyDebug::MyDebug()
{
}


MyDebug::~MyDebug()
{
    FreeList();
    if (m_pDebugFilePath)
    {
        delete[]m_pDebugFilePath;
    }
    if (m_pFile != NULL)
    {
        fclose(m_pFile);
    }
}

void MyDebug::Run()
{
    printf("*******************************************************\r\n");
    printf("*                                                     *\r\n");
    printf("*                     MyDebug                         *\r\n");
    printf("*                     Version: 1.0                    *\r\n");
    printf("*                     2019/11/17                      *\r\n");
    printf("*                                                     *\r\n");
    printf("*******************************************************\r\n\r\n");

    printf(">>提示： 按回车键选择调试文件\r\n");
    while (!_kbhit());//接受任意键
    getchar();

    while (true)
    {
        m_pDebugFilePath = GetDebugFilePath();
        if (m_pDebugFilePath)
        {
            break;
        }
    }
    

    //创建调试进程
    m_si.cb = sizeof(m_si);

    if (!CreateProcess(m_pDebugFilePath,
        NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS,
        NULL,
        NULL,
        &m_si,
        &m_pi)) 
    {
        MyErrorReport::ShowGetLastError("Run->CreateProcess");
        return;
    }

    system("cls");
    printf("**********************************************************************\r\n");
    printf("*      指令      参数1       参数2       参数3        操作           *\r\n");
    printf("*     ------------------------------------------------------------   *\r\n");
    printf("*  >> | t   |     无     |    无     |    无     |   单步步入     |  *\r\n");
    printf("*  >> | p   |     无     |    无     |    无     |   单步步过     |  *\r\n");
    printf("*  >> | g   |   无/地址  |    无     |    无     |     运行       |  *\r\n");
    printf("*  >> |trace|  起始地址  |  结束地址 | 无/模块名 |  自动跟踪记录  |  *\r\n");
    printf("*  >> | u   |   无/地址  |    无     |    无     |    反汇编      |  *\r\n");
    printf("*  >> | dd  |   无/地址  |    无     |    无     |  显示内存数据  |  *\r\n");
    printf("*  >> | r   |     无     |    无     |    无     |     寄存器     |  *\r\n");
    printf("*  >> | e   |   无/地址  |    无     |    无     |  修改内存数据  |  *\r\n");
    printf("*  >> | bp  |    地址    |   无/sys  |    无     |    一般断点    |  *\r\n");
    printf("*  >> | bpl |     无     |    无     |    无     |   一般断点列表 |  *\r\n");
    printf("*  >> | bpc |    序号    |    无     |    无     |   删除一般断点 |  *\r\n");
    printf("*  >> | bh  |    地址    |   e/w/a   |   1/2/4   |   硬件断点     |  *\r\n");
    printf("*  >> | bhl |     无     |    无     |    无     |  硬件断点列表  |  *\r\n");
    printf("*  >> | bhc |    序号    |    无     |    无     |  删除硬件断点  |  *\r\n");
    printf("*  >> | bm  |    地址    |   长度    |    r/w    |     内存断点   |  *\r\n");
    printf("*  >> | bml |     无     |    无     |    无     |  内存断点列表  |  *\r\n");
    printf("*  >> | bmpl|     无     |    无     |    无     |  分页断点列表  |  *\r\n");
    printf("*  >> | bmc |    序号    |    无     |    无     |  删除内存断点  |  *\r\n");
    printf("*  >> | ls  |     无     |    无     |    无     |   导入脚本     |  *\r\n");
    printf("*  >> | es  |     无     |    无     |    无     |   导出脚本     |  *\r\n");
    printf("*  >> | q   |     无     |    无     |    无     |   退出程序     |  *\r\n");
    printf("*  >> | ml  |     无     |    无     |    无     |   查看模块     |  *\r\n");
    printf("*  >> -------------------------------------------------------------  *\r\n");
    printf("**********************************************************************\r\n\r\n");


    for (;;)
    {
        //等待调试事件
        WaitForDebugEvent(&m_DebugEv, INFINITE);

        //检查调试事件
        switch (m_DebugEv.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
            m_dwContinueStatus = ExceptionDebugEvent();
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            m_dwContinueStatus = CreateThreadDebugEvnet();
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            m_dwContinueStatus = CreateProcessDebugEvnet();
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            m_dwContinueStatus = ExitThreadDebugEvnet();
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            m_dwContinueStatus = ExitProcessDebugEvnet();
            break;
        case LOAD_DLL_DEBUG_EVENT:
            m_dwContinueStatus = LoadDllDebugEvnet();
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
            m_dwContinueStatus = UnloadDllDebugEvnet();
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            m_dwContinueStatus = OutputStringDebugEvnet();
            break;
        case RIP_EVENT:
            m_dwContinueStatus = RipDebugEvnet();
            break;
        }

        if (m_bIsExit)
        {
            return;
        }

        //继续执行线程，重新报告调试事件
        ContinueDebugEvent(m_DebugEv.dwProcessId, m_DebugEv.dwThreadId, m_dwContinueStatus);
    }
}

//读脚本
bool MyDebug::GetScriptInfo(DEBUGORDER* pOrder)
{
    fscanf(m_pFile, "%s\n", pOrder->szCMD);
    fscanf(m_pFile, "%s\n", pOrder->szModule);
    if (strcmp(pOrder->szModule, "NULL") == 0)
    {
        memset(pOrder->szModule, 0, MODULE_SIZE);
    }
    fscanf(m_pFile, "%d-%d-%d-%d", &pOrder->Other.nNum, (int*)&pOrder->pAddrBegin, (int*)&pOrder->pAddrEnd, &pOrder->cType);

    if (feof(m_pFile))
    {
        //读完了，关闭
        fclose(m_pFile);
        return false;
    }

    return true;
}

//获取用户输入，写入结构体
void MyDebug::GetUserInput(DEBUGORDER* pOrder)
{
    char szBuff[100] = { 0 };

    while (true)
    {
        printf(">>command:");
        gets_s(szBuff, 100);
        _strlwr_s(szBuff);//转小写

        //防止bm替代bml，所以有一下操作
        char szTemp[100] = { 0 };
        strcpy_s(szTemp, 100, szBuff);
        for (int i = 0; i < 100; i++)
        {
            if (szTemp[i] == ' ')
            {
                szTemp[i] = '\0';
                break;
            }
        }

        if (strcmp(szTemp, "t") == 0 || strcmp(szTemp, "p") == 0 || strcmp(szTemp, "r") == 0 ||
            strcmp(szTemp, "bpl") == 0 || strcmp(szTemp, "bhl") == 0 || strcmp(szTemp, "bml") == 0 ||
            strcmp(szTemp, "bmpl") == 0 || strcmp(szTemp, "ls") == 0 || strcmp(szTemp, "es") == 0 ||
            strcmp(szTemp, "q") == 0 || strcmp(szTemp, "ml") == 0)//无参数
        {
            strcpy_s(pOrder->szCMD, CMD_SIZE, szBuff);
            break;
        }
        else if (strcmp(szTemp, "g") == 0 || strcmp(szTemp, "u") == 0 ||
            strcmp(szTemp, "dd") == 0 || strcmp(szTemp, "e") == 0)//一个可有可无的地址参数
        {
            char seps[] = " \n";
            char *token = strtok(szBuff, seps);
            strcpy_s(pOrder->szCMD, CMD_SIZE, token);

            token = strtok(NULL, seps);
            if (token != NULL)
            {
                if (strlen(token) > 8)
                {
                    MyErrorReport::ShowNormalError("输入错误！");
                    continue;
                }
                pOrder->pAddrBegin = (void*)strtoul(token, NULL, 16);
            }
            break;
        }
        else if (strcmp(szTemp, "bpc") == 0 || strcmp(szTemp, "bhc") == 0 ||
            strcmp(szTemp, "bmc") == 0)//有一个参数为序号
        {
            char seps[] = " \n";
            char *token = strtok(szBuff, seps);
            strcpy_s(pOrder->szCMD, CMD_SIZE, token);

            token = strtok(NULL, seps);
            if (token != NULL)
            {
                pOrder->Other.nNum = strtoul(token, NULL, 16);
            }
            break;
        }
        else if (strcmp(szTemp, "trace") == 0)
        {
            char seps[] = " \n";
            char szTemp[100] = { 0 };

            char *token = strtok(szBuff, seps);//trace
            strcpy_s(pOrder->szCMD, CMD_SIZE, token);

            token = strtok(NULL, seps);        //地址1
            strcpy_s(szTemp, 100, token);
            pOrder->pAddrBegin = (void*)strtoul(szTemp, NULL, 16);

            token = strtok(NULL, seps);        //地址2
            strcpy_s(szTemp, 100, token);
            pOrder->pAddrEnd = (void*)strtoul(szTemp, NULL, 16);

            token = strtok(NULL, seps);
            if (token != NULL)
            {
                strcpy_s(pOrder->szModule, MODULE_SIZE, token);//模块地址
            }

            break;
        }
        else if (strcmp(szTemp, "bp") == 0)
        {
            char seps[] = " \n";
            char szTemp[100] = { 0 };

            char *token = strtok(szBuff, seps);//trace
            strcpy_s(pOrder->szCMD, CMD_SIZE, token);

            token = strtok(NULL, seps);        //地址1
            strcpy_s(szTemp, 100, token);
            pOrder->pAddrBegin = (void*)strtoul(szTemp, NULL, 16);

            token = strtok(NULL, seps);        //参数2
            pOrder->Other.bOnce = false;
            if (token != NULL)
            {
                if (strcmp(token, "sys") == 0)
                {
                    pOrder->Other.bOnce = true;
                }
            }
            break;
        }
        else if (strcmp(szTemp, "bh") == 0)
        {
            char seps[] = " \n";
            char szTemp[100] = { 0 };

            char *token = strtok(szBuff, seps);//bh
            strcpy_s(pOrder->szCMD, CMD_SIZE, token);

            token = strtok(NULL, seps);        //地址1
            if (token == NULL)
            {
                MyErrorReport::ShowNormalError("输入错误！");
                continue;
            }
            strcpy_s(szTemp, 100, token);
            pOrder->pAddrBegin = (void*)strtoul(szTemp, NULL, 16);

            token = strtok(NULL, seps);        //参数2
            if (token == NULL)
            {
                MyErrorReport::ShowNormalError("输入错误！");
                continue;
            }
            pOrder->cType = token[0];

            token = strtok(NULL, seps);        //参数3
            if (token == NULL)
            {
                MyErrorReport::ShowNormalError("输入错误！");
                continue;
            }
            strcpy_s(szTemp, 100, token);
            pOrder->Other.nBpLenth = strtoul(szTemp, NULL, 16);
            break;
        }
        else if (strcmp(szTemp, "bm") == 0)
        {
            char seps[] = " \n";
            char szTemp[100] = { 0 };

            char *token = strtok(szBuff, seps);//bm
            strcpy_s(pOrder->szCMD, CMD_SIZE, token);

            token = strtok(NULL, seps);        //地址1
            if (token == NULL)
            {
                MyErrorReport::ShowNormalError("输入错误！");
                continue;
            }
            strcpy_s(szTemp, 100, token);
            pOrder->pAddrBegin = (void*)strtoul(szTemp, NULL, 16);

            token = strtok(NULL, seps);        //参数2
            if (token == NULL)
            {
                MyErrorReport::ShowNormalError("输入错误！");
                continue;
            }
            strcpy_s(szTemp, 100, token);
            pOrder->Other.nBpLenth = strtoul(szTemp, NULL, 10);

            token = strtok(NULL, seps);        //参数3
            if (token == NULL)
            {
                MyErrorReport::ShowNormalError("输入错误！");
                continue;
            }
            pOrder->cType = token[0];
            break;
        }
        else
        {
            MyErrorReport::ShowNormalError("输入错误！");
            continue;
        }
    }
}

DWORD MyDebug::GetCommand()
{
    DWORD dwContinueStatus = DBG_CONTINUE;
    void* uAddr = NULL;
    DEBUGORDER dbOrder;
    ZeroMemory(&dbOrder, sizeof(DEBUGORDER));

    while (true)
    {
        if (m_bExecuteRecordFile)
        {
            //读脚本
            if (!GetScriptInfo(&dbOrder))
            {
                //如果读完了，就接受输入
                m_bExecuteRecordFile = false;
                GetUserInput(&dbOrder);
            }
        }
        else
        {
            //用户输入
            GetUserInput(&dbOrder);
        }
        
        //执行指令
        if (strcmp(dbOrder.szCMD, "g") == 0)
        {
            SavaOrder(&dbOrder);
            if (dbOrder.pAddrBegin != 0)
            {
                CmdSetGoBreakPoint(dbOrder.pAddrBegin);
            }
            m_bIsExecuteCode = true;
            break;
        }
        else if (strcmp(dbOrder.szCMD, "t") == 0)
        {
            //单步步入
            CmdSetStepInto();
            SavaOrder(&dbOrder);
            m_bIsExecuteCode = true;
            break;
        }
        else if (strcmp(dbOrder.szCMD, "p") == 0)
        {
            //单步步过
            CmdSetStepOver();
            SavaOrder(&dbOrder);
            m_bIsExecuteCode = true;
            break;
        }
        else if (strcmp(dbOrder.szCMD, "trace") == 0)
        {
            m_bTrace = true;
            m_nTraceBegin = (int)dbOrder.pAddrBegin;
            m_nTraceEnd = (int)dbOrder.pAddrEnd;
            m_bIsExecuteCode = true;
            if (strlen(dbOrder.szModule) == 0)//没有跟踪模块
            {
                m_bTraceModule = false;
            }
            else
            {
                m_bTraceModule = true;
                if (!GetMoDuleRange(dbOrder.szModule))
                {
                    MyErrorReport::ShowNormalError("当前进程没有加载此模块！");
                    m_bTraceModule = false;
                }
            }
            SavaOrder(&dbOrder);
            //不管有没有此文件都删除
            DeleteFile("Trace.txt");
        }
        else if (strcmp(dbOrder.szCMD, "u") == 0)
        {
            m_bIsExecuteCode = true;
            if (dbOrder.pAddrBegin == 0)
            {
                uAddr = ShowDisassembler(uAddr, 10);
            }
            else
            {
                uAddr = ShowDisassembler(dbOrder.pAddrBegin, 10);
            }
            SavaOrder(&dbOrder);
        }
        else if (strcmp(dbOrder.szCMD, "dd") == 0)
        {
            m_bIsExecuteCode = true;
            m_pShowMemory = ShowMemoryData(dbOrder.pAddrBegin);
            SavaOrder(&dbOrder);
        }
        else if (strcmp(dbOrder.szCMD, "r") == 0)
        {
            m_bIsExecuteCode = true;
            ShowRegister();
            SavaOrder(&dbOrder);
        }
        else if (strcmp(dbOrder.szCMD, "e") == 0)
        {
            m_bIsExecuteCode = true;
            m_pEditMemoryData = EditMemoryData(dbOrder.pAddrBegin);
            SavaOrder(&dbOrder);
        }
        else if (strcmp(dbOrder.szCMD, "bp") == 0)
        {
            m_bIsExecuteCode = true;
            if (!CmdSetBreakPoint(dbOrder.pAddrBegin, dbOrder.Other.bOnce))
            {
                MyErrorReport::ShowNormalError("断点设置失败");
            }
            else
            {
                SavaOrder(&dbOrder);
            }
        }
        else if (strcmp(dbOrder.szCMD, "bpl") == 0)
        {
            m_bIsExecuteCode = true;
            ShowNormalBreakPoint();
            SavaOrder(&dbOrder);
        }
        else if (strcmp(dbOrder.szCMD, "bpc") == 0)
        {
            m_bIsExecuteCode = true;
            if (!DeleteNormalBreakPoint(dbOrder.Other.nNum))
            {
                MyErrorReport::ShowNormalError("该编号的断点不存在！");
            }
            else
            {
                SavaOrder(&dbOrder);
                printf("该断点已成功删除！\r\n");
            }
        }
        else if (strcmp(dbOrder.szCMD, "bh") == 0)
        {
            m_bIsExecuteCode = true;
            if (m_nHardBreakPointNum >= 4)
            {
                printf("硬件断点个数已经达到上限！\r\n");
            }
            else
            {
                if (!CmdSetHardBreakPoint(dbOrder.pAddrBegin, dbOrder.cType, dbOrder.Other.nBpLenth))
                {
                    MyErrorReport::ShowNormalError("断点设置失败");
                }
                else
                {
                    SavaOrder(&dbOrder);
                }
            }
        }
        else if (strcmp(dbOrder.szCMD, "bhl") == 0)
        {
            m_bIsExecuteCode = true;
            ShowHardBreakPoint();
            SavaOrder(&dbOrder);
        }
        else if (strcmp(dbOrder.szCMD, "bhc") == 0)
        {
            m_bIsExecuteCode = true;
            if (!DeleteHardBreakPoint(dbOrder.Other.nNum))
            {
                MyErrorReport::ShowNormalError("该编号的断点不存在！");
            }
            else
            {
                SavaOrder(&dbOrder);
                printf("该断点已成功删除！\r\n");
            }
        }
        else if (strcmp(dbOrder.szCMD, "bm") == 0)
        {
            m_bIsExecuteCode = true;
            if (!CmdSetMemoryBreakPoint(dbOrder.pAddrBegin, dbOrder.cType, dbOrder.Other.nBpLenth))
            {
                MyErrorReport::ShowNormalError("断点设置失败");
            }
            else
            {
                SavaOrder(&dbOrder);
            }
        }
        else if (strcmp(dbOrder.szCMD, "bml") == 0)
        {
            m_bIsExecuteCode = true;
            ShowMemoryBreakPoint();
            SavaOrder(&dbOrder);
        }
        else if (strcmp(dbOrder.szCMD, "bmpl") == 0)
        {
            m_bIsExecuteCode = true;
            ShowPageBreakPoint();
            SavaOrder(&dbOrder);
        }
        else if (strcmp(dbOrder.szCMD, "bmc") == 0)
        {
            m_bIsExecuteCode = true;
            if (!DeleteMemoryBreakPoint(dbOrder.Other.nNum))
            {
                MyErrorReport::ShowNormalError("该编号的断点不存在！");
            }
            else
            {
                SavaOrder(&dbOrder);
                printf("该断点已成功删除！\r\n");
            }
        }
        else if (strcmp(dbOrder.szCMD, "ls") == 0)
        {
            ImportScript();
        }
        else if (strcmp(dbOrder.szCMD, "es") == 0)
        {
            m_bIsExecuteCode = true;
            ExportScript();
        }
        else if (strcmp(dbOrder.szCMD, "q") == 0)
        {
            m_bIsExit = true;
            break;
        }
        else if (strcmp(dbOrder.szCMD, "ml") == 0)
        {
            m_bIsExecuteCode = true;
            ShowModule();
            SavaOrder(&dbOrder);
        }
        else
        {

        }
    }

    return dwContinueStatus;
}

char * MyDebug::GetDebugFilePath()
{
    char* pBuffer = new char[MAX_PATH];
    if (pBuffer == nullptr)
    {
        MyErrorReport::ShowNormalError("GetDebugFilePath : 内存申请失败！");
        return nullptr;
    }
    memset(pBuffer, 0, MAX_PATH);

    OPENFILENAME file = { 0 };
    file.hwndOwner = NULL;
    file.lStructSize = sizeof(file);
    file.lpstrFilter = ("Exe文件(*.exe)\0*.exe\0所有文件(*.*)\0*.*\0");//要选择的文件后缀exe
    file.lpstrInitialDir = ("C:\\");//默认的文件路径 
    file.lpstrFile = pBuffer;//存放文件的缓冲区 
    file.nMaxFile = MAX_PATH;
    file.nFilterIndex = 0;
    file.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;//标志如果是多选要加上OFN_ALLOWMULTISELECT
    BOOL bSel = GetOpenFileName(&file);
    if (bSel == NULL)
    {
        MyErrorReport::ShowGetLastError("GetOpenFileName");
        delete[]pBuffer;
        return nullptr;
    }
    
    return pBuffer;
}

void MyDebug::SavaOrder(DEBUGORDER* pOrder)
{
    //保存指令
    DEBUGORDER* pMyOrder = new DEBUGORDER;
    memcpy(pMyOrder, pOrder, sizeof(DEBUGORDER));
    m_lstExecuteOrder.push_back(pMyOrder);
}

void MyDebug::SavaDebugState()
{

}

DWORD MyDebug::ExceptionBreakPoint()//断点异常
{
    DWORD dwContinueStatus = DBG_CONTINUE;

    if (m_nGoAddr)
    {
        CONTEXT context;
        MyGetContext(m_DebugEv.dwThreadId, context);

        if (context.Eip - 1 == m_nGoAddr)
        {
            context.Eip -= 1;
            MySetContext(m_DebugEv.dwThreadId, context);

            //还原指令
            MyWriteProcessMomory(m_DebugEv.dwProcessId, (void*)context.Eip, &m_cGoCode, 1);
            ShowDisassembler(NULL, 1);
            dwContinueStatus = GetCommand();
            return dwContinueStatus;
        }
    }

    if (m_bIsSystem)
    {
        m_bIsSystem = false;
        //等待用户命令
        dwContinueStatus = GetCommand();
        return dwContinueStatus;
    }

    //从断点链表获取断点信息
    m_pCurrentBreakPoint = GetBreakPointInfo();
    if (m_pCurrentBreakPoint == nullptr)
    {
        MyErrorReport::ShowNormalError("断点信息出错，请重启调试器");
        system("pause");
        return dwContinueStatus;
    }
    m_bIsNormalBreakPoint = true;

    //eip - 1，当前IP已经跳过断点，所以要 -1
    CONTEXT context;
    MyGetContext(m_DebugEv.dwThreadId, context);
    context.Eip -= 1;
    context.EFlags |= TF_FALG;//设置单步

    MySetContext(m_DebugEv.dwThreadId, context);

    //还原指令
    MyWriteProcessMomory(m_DebugEv.dwProcessId, (void*)context.Eip, &m_pCurrentBreakPoint->Other.cOld, 1);

    ShowDisassembler(NULL, 1);

    dwContinueStatus = GetCommand();

    return dwContinueStatus;
}

DWORD MyDebug::ExceptionAccess()//内存访问异常
{
    DWORD dwContinueStatus = DBG_CONTINUE;
    DWORD dwAddr = m_DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[1];

    //还原内存保护属性
    for (auto item = m_lstMemoryBreakPoint.begin(); item != m_lstMemoryBreakPoint.end(); item++)
    {
        if (dwAddr >= (DWORD)(*item)->Other.nPage && dwAddr < (DWORD)(*item)->Other.nPage + 0X1000)
        {
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_DebugEv.dwProcessId);
            if (hProcess == NULL)
            {
                MyErrorReport::ShowGetLastError("ExceptionAccess->OpenProcess");
                CloseHandle(hProcess);
                return dwContinueStatus;
            }
            DWORD dwRet = 0;
            if (!VirtualProtectEx(hProcess, (*item)->pAddr, 1, (*item)->dwOldType, &dwRet))
            {
                MyErrorReport::ShowGetLastError("ExceptionAccess->OpenProcess");
                CloseHandle(hProcess);
                return dwContinueStatus;
            }
            CloseHandle(hProcess);
            break;
        }
    }

    //设置单步
    CmdSetStepInto();
    m_pMemoryExceptionAddr = (void*)dwAddr;

    for (auto item = m_lstMemoryBreakPoint.begin(); item != m_lstMemoryBreakPoint.end(); item++)
    {
        //判断异常点是否在设置的区间内
        if ((*item)->pAddr <= (void*)dwAddr && dwAddr <= (int)(*item)->pAddr + (*item)->nSize)
        {
            ShowDisassembler(NULL, 1);
            //m_pCurrentBreakPoint = *item;
            //m_bIsMemoryBreakPoint = true;
            GetCommand();
            return dwContinueStatus;
        }
    }

    return dwContinueStatus;
}

DWORD MyDebug::ExceptionSingleStep()//单步异常
{
    DWORD dwContinueStatus = DBG_CONTINUE;

    //硬件断点设置的单步，还原断点
    if (m_bIsHardBreakPoint)
    {
        CONTEXT context;
        MyGetContext(m_DebugEv.dwThreadId, context);
        for (auto item = m_lstHardBreakPoint.begin(); item != m_lstHardBreakPoint.end(); item++)
        {
            DR7 dr7 = { 0 };
            dr7.dr7 = context.Dr7;

            switch ((*item)->Other.nDRNum)
            {
            case 0:
            {
                context.Dr0 = (DWORD)(*item)->pAddr;
                dr7.L0 = 1;
                break;
            }
            case 1:
            {
                context.Dr1 = (DWORD)(*item)->pAddr;
                dr7.L1 = 1;
                break;
            }
            case 2:
            {
                context.Dr2 = (DWORD)(*item)->pAddr;
                dr7.L2 = 1;
                break;
            }
            case 3:
            {
                context.Dr3 = (DWORD)(*item)->pAddr;
                dr7.L3 = 1;
                break;
            }
            default:break;
            }
            context.ContextFlags = CONTEXT_ALL;
            context.Dr7 = dr7.dr7;
            MySetContext(m_DebugEv.dwThreadId, context);
        }

        m_bIsHardBreakPoint = false;
        //return dwContinueStatus;
    }

    //内存异常单步
    if (m_pMemoryExceptionAddr)
    {
        //设置回用户设置的内存保护属性
        for (auto item = m_lstMemoryBreakPoint.begin(); item != m_lstMemoryBreakPoint.end(); item++)
        {
            if ((*item)->Other.nPage <= m_pMemoryExceptionAddr && m_pMemoryExceptionAddr <= (void*)((int)(*item)->Other.nPage + 0X1000))
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_DebugEv.dwProcessId);
                if (hProcess == NULL)
                {
                    MyErrorReport::ShowGetLastError("ExceptionSingleStep->OpenProcess");
                    CloseHandle(hProcess);
                    return dwContinueStatus;
                }
                DWORD dwRet = 0;
                if ((*item)->cType == 'r')
                {
                    if (!VirtualProtectEx(hProcess, m_pMemoryExceptionAddr, 1, PAGE_NOACCESS, &dwRet))
                    {
                        MyErrorReport::ShowGetLastError("CmdSetMemoryBreakPoint->VirtualProtectEx");
                        return false;
                    }
                }
                else
                {
                    if (!VirtualProtectEx(hProcess, m_pMemoryExceptionAddr, 1, PAGE_EXECUTE_READ, &dwRet))
                    {
                        MyErrorReport::ShowGetLastError("CmdSetMemoryBreakPoint->VirtualProtectEx");
                        return false;
                    }
                }
                break;
            }
        }
        m_pMemoryExceptionAddr = nullptr;
        return dwContinueStatus;
    }

    //一般断点 重新写入cc, 指令执行完毕
    if (m_bIsNormalBreakPoint)
    {
        if (m_pCurrentBreakPoint)
        {
            for (auto item = m_lstNormalBreakPoint.begin(); item != m_lstNormalBreakPoint.end(); item++)
            {
                if ((*item) == m_pCurrentBreakPoint)
                {
                    if (!m_pCurrentBreakPoint->isOnce)
                    {
                        unsigned char code = 0xcc;
                        MyWriteProcessMomory(m_DebugEv.dwProcessId, m_pCurrentBreakPoint->pAddr, &code, 1);

                        ShowDisassembler(NULL, 1);
                        dwContinueStatus = GetCommand();
                        m_pCurrentBreakPoint = nullptr;
                        m_bIsNormalBreakPoint = false;
                        return dwContinueStatus;
                    }
                    else
                    {
                        m_lstNormalBreakPoint.erase(item);
                        break;
                    }
                }
            }
        }
        m_pCurrentBreakPoint = nullptr;
        m_bIsNormalBreakPoint = false;
    }
    
    //硬件断点第一次来
    int nBPNum = FindHardBreakPoint();
    if (nBPNum != -1)
    {
        CONTEXT context;
        MyGetContext(m_DebugEv.dwThreadId, context);

        DR7 dr7 = { 0 };
        dr7.dr7 = context.Dr7;

        switch (nBPNum)
        {
        case 0:
        {
            context.Dr0 = 0;
            dr7.L0 = 0;
            break;
        }
        case 1:
        {
            context.Dr1 = 0;
            dr7.L1 = 0;
            break;
        }
        case 2:
        {
            context.Dr2 = 0;
            dr7.L2 = 0;
            break;
        }
        case 3:
        {
            context.Dr3 = 0;
            dr7.L3 = 0;
            break;
        }
        default:break;
        }
        context.ContextFlags = CONTEXT_ALL;
        context.EFlags |= TF_FALG;
        context.Dr7 = dr7.dr7;
        MySetContext(m_DebugEv.dwThreadId, context);
        m_bIsHardBreakPoint = true;
    }

    ShowDisassembler(NULL, 1);

    //等待用户命令
    dwContinueStatus = GetCommand();

    return dwContinueStatus;
}

void* MyDebug::ShowDisassembler(void * addr, int line)
{
    EXCEPTION_RECORD& ExceptionRecord = m_DebugEv.u.Exception.ExceptionRecord;
    unsigned char szBuff[160] = { 0 };
    unsigned char* pBuff = szBuff;
    char szAsmCode[256] = { 0 };//反汇编指令
    char szOpCode[256] = { 0 };//机器码
    int nSize = 0;

    if (addr == NULL)
    {
        CONTEXT context;
        MyGetContext(m_DebugEv.dwThreadId, context);
        addr = (void*)context.Eip;
    }

    MyReadProcessMomory(m_DebugEv.dwProcessId, addr, szBuff, sizeof(szBuff));

    //解析二进制为汇编代码
    for (int i = 0; i < line; i++)
    {
        Decode2AsmOpcode((PBYTE)pBuff, szAsmCode, szOpCode, (UINT*)&nSize, (UINT)addr);

        //检测，如果是int 3 则先还原，再解析
        if (strncmp(szOpCode, "CC", 2) == 0)
        {
            unsigned char cOld = 0;
            unsigned char cInt3 = 0xCC;
            //遍历一般断点链表找到原来的代码
            for (auto item = m_lstNormalBreakPoint.begin(); item != m_lstNormalBreakPoint.end(); item++)
            {
                if (addr == (*item)->pAddr)
                {
                    cOld = (*item)->Other.cOld;
                }
            }

            //还原
            pBuff[0] = cOld;

            //再解析
            Decode2AsmOpcode((PBYTE)pBuff, szAsmCode, szOpCode, (UINT*)&nSize, (UINT)addr);
        }

        printf("%p:  %-22s  %s\r\n", addr, szOpCode, szAsmCode);

        if (m_bTrace)
        {
            if (line == 1)
            {
                char szShow[0X100] = { 0 };
                wsprintf(szShow, "%p:  %-22s  %s", addr, szOpCode, szAsmCode);
                SetTraceInfo((int)addr, szShow);
            }
            
        }
       
        pBuff = (unsigned char*)((int)pBuff + nSize);
        addr = (void*)((int)addr + nSize);
    }
    return addr;
}

void  MyDebug::ShowRegister()
{
    CONTEXT context;
    MyGetContext(m_DebugEv.dwThreadId, context);

    printf("EAX = %p   EBX = %p   ECX = %p   EDX = %p   ESP = %p   EBP = %p\r\n",
        context.Eax, context.Ebx, context.Ecx, context.Edx, context.Esp, context.Ebp);
    printf("ESI = %p   EDi = %p   EIP = %p   CS = %04X    SS = %04X    DS = %04X   ES  = %04X\r\n",
        context.Esi, context.Edi, context.Eip, context.SegCs, context.SegSs, context.SegDs, context.SegEs);
    printf("FS  = %04X    GS  = %04X     ",context.SegFs, context.SegGs);

    //标志寄存器信息
    EFLAG eflag;
    eflag .nEflag = context.EFlags;

    printf("CF = %d  PF = %d  AF = %d  ZF = %d  SF = %d  TF = %d  IF = %d  DF = %d  OF = %d\r\n",
        eflag.CF, eflag.PF, eflag.AF, eflag.ZF, eflag.SF, eflag.TF, eflag.IF, eflag.DF, eflag.OF);

    //错误码
    DWORD error;
    MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)m_pTeb + 0x34, (unsigned char*)&error, sizeof(error));
    printf("GetLastError : %X\n", error);

    return ;
}

void  MyDebug::ShowModule()
{
    DWORD dwAddr = 0;
    MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)m_pTeb + 0x30, (unsigned char*)&dwAddr, sizeof(dwAddr));
    MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x0c, (unsigned char*)&dwAddr, sizeof(dwAddr));
    MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x0c, (unsigned char*)&dwAddr, sizeof(dwAddr));

    DWORD dwBegin = dwAddr;
    do 
    {
        char szName[100] = { 0 };
        DWORD dwTemp = 0;
        MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x30, (unsigned char*)&dwTemp, sizeof(dwTemp));
        MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwTemp, (unsigned char*)szName, 100);

        if (wcslen((wchar_t*)szName) != 0)
        {
            wprintf(L"%-20s", (wchar_t*)szName);

            //计算进程的模块范围
            int nModuleBase = 0;
            MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x18, (unsigned char*)&nModuleBase, sizeof(nModuleBase));

            printf("%p\r\n", nModuleBase);
        }
        
        MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr, (unsigned char*)&dwAddr, sizeof(dwAddr));
    } while (dwAddr != dwBegin);
    return;
}

void * MyDebug::ShowMemoryData(void * pAddr)
{
    unsigned char szData[128] = { 0 };
    void* pBegin = 0;
    if (pAddr == nullptr)//无地址参数
    {
        MyReadProcessMomory(m_DebugEv.dwProcessId, m_pShowMemory, (unsigned char*)szData, sizeof(szData));
        pBegin = (char*)m_pShowMemory;
    }
    else//有地址参数
    {
        MyReadProcessMomory(m_DebugEv.dwProcessId, pAddr, (unsigned char*)szData, sizeof(szData));
        pBegin = (char*)pAddr;
    }

    //分8行显示
    for (int i = 0; i < 128; i++)
    {
        if (i % 16 == 0)
        {
            printf("%p    ", pBegin);
        }
        printf("%02X ", szData[i]);
        if (i % 16 == 15)
        {
            printf("    ");
            for (int j = 15; j >= 0; j--)
            {
                if (szData[i - j] >= 32 && szData[i - j] <= 126)
                {
                    printf("%c", szData[i - j]);
                }
                else
                {
                    printf(".");
                }
            }
            printf("\r\n");
        }
        pBegin = (char*)pBegin + 1;
    }

    return pBegin;
}

void MyDebug::ShowNormalBreakPoint()
{
    int nNum = 1;
    for (auto item = m_lstNormalBreakPoint.begin(); item != m_lstNormalBreakPoint.end(); item++)
    {
        printf(">>断点编号：%2d    断点地址：%p    ", nNum, (*item)->pAddr);
        if ((*item)->isOnce)
        {
            printf("是否一次断点 ：是\r\n");
        }
        else
        {
            printf("是否一次断点 ：不是\r\n");
        }

        nNum++;
    }
}

void MyDebug::ShowHardBreakPoint()
{
    int nNum = 1;
    for (auto item = m_lstHardBreakPoint.begin(); item != m_lstHardBreakPoint.end(); item++)
    {
        printf(">>断点编号：%2d    断点地址：%p    ", nNum, (*item)->pAddr);
        
        printf("寄存器：Dr%d   ", (*item)->Other.nDRNum);

        switch ((*item)->cType)
        {
        case 'e':
        {
            printf("执行断点   ");
            break;
        }
        case 'w':
        {
            printf("写入断点   ");
            break;
        }
        case 'a':
        {
            printf("访问断点   ");
            break;
        }
        }
        printf("断点长度：%d字节 \r\n", (*item)->nSize);

        nNum++;
    }
}

void MyDebug::ShowMemoryBreakPoint()
{
    int nNum = 1;
    for (auto item = m_lstMemoryBreakPoint.begin(); item != m_lstMemoryBreakPoint.end(); item++)
    {
        printf(">>断点编号：%2d    断点地址：%p    ", nNum, (*item)->pAddr);

        switch ((*item)->cType)
        {
        case 'r':
        {
            printf("读断点   ");
            break;
        }
        case 'w':
        {
            printf("写断点   ");
            break;
        }
        }
        printf("断点长度：%d字节   ", (*item)->nSize);
        printf("断点分页：%p \r\n", (*item)->Other.nPage);
        nNum++;
    }
}

void MyDebug::ShowPageBreakPoint()
{
    vector<void*> vePage;
    for (auto item = m_lstMemoryBreakPoint.begin(); item != m_lstMemoryBreakPoint.end(); item++)
    {
        bool bFlag = false;//判断当前分页是否被输出过
        for (auto itemPage = vePage.begin(); itemPage != vePage.end(); itemPage++)
        {
            if (*itemPage == (*item)->Other.nPage)
            {
                bFlag = true;
                break;
            }
        }

        if (bFlag)
        {
            continue;
        }
        else
        {
            vePage.push_back((*item)->Other.nPage);
            printf("\r\n>>分页：%p\r\n", (*item)->Other.nPage);
            int nPage = 1;
            for (auto itemAddr = m_lstMemoryBreakPoint.begin(); itemAddr != m_lstMemoryBreakPoint.end(); itemAddr++)
            {
                if ((*item)->Other.nPage == (*itemAddr)->Other.nPage)
                {
                    printf(">>%d 断点地址:%p   ", nPage++, (*itemAddr)->pAddr);

                    if ((*itemAddr)->cType == 'r')
                    {
                        printf("读断点   ");
                    }
                    else
                    {
                        printf("写断点   ");
                    }

                    printf("断点尺寸：%d\r\n", (*itemAddr)->nSize);
                }
            }
        }
    }
}

DWORD MyDebug::MyReadProcessMomory(DWORD pid, void * addr, unsigned char * buffer, DWORD len)
{
    DWORD dwBytes;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        MyErrorReport::ShowGetLastError("MyReadProcessMomory->OpenProcess");
        return false;
    }
    ReadProcessMemory(hProcess, addr, buffer, len, &dwBytes);
    CloseHandle(hProcess);
    return dwBytes;
}

DWORD MyDebug::MyWriteProcessMomory(DWORD pid, void * addr, unsigned char * buffer, DWORD len)
{
    DWORD dwBytes;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        MyErrorReport::ShowGetLastError("MyWriteProcessMomory->OpenProcess");
        return false;
    }
    WriteProcessMemory(hProcess, addr, buffer, len, &dwBytes);
    CloseHandle(hProcess);
    return dwBytes;
}

DWORD MyDebug::MyGetContext(DWORD tid, CONTEXT & context)
{
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &context);
    CloseHandle(hThread);
    return 0;
}

DWORD MyDebug::MySetContext(DWORD tid, CONTEXT & context)
{
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    context.ContextFlags = CONTEXT_ALL;
    SetThreadContext(hThread, &context);
    CloseHandle(hThread);
    return 0;
}

bool MyDebug::JudgeIsCall(DWORD pIpAddr)
{
    unsigned char szBuff[100] = { 0 };
    char szAsmCode[100] = { 0 };//反汇编指令
    char szOpCode[100] = { 0 };//机器码
    int nSize = 0;
    void* pCallAddr = nullptr;
    MyReadProcessMomory(m_DebugEv.dwProcessId, (void*)pIpAddr, szBuff, sizeof(szBuff));
    Decode2AsmOpcode((PBYTE)szBuff, szAsmCode, szOpCode, (UINT*)&nSize, (UINT)pIpAddr);

    if (strncmp(szAsmCode, "call", 4) == 0)
    {
        //找到了call，现在转化地址,在call的下一条指令下个一次性断点
        int nSize = (strlen(szOpCode) - 1) / 2;
        pCallAddr = (void*)(pIpAddr + nSize);
        CmdSetBreakPoint(pCallAddr, true);
        return true;
    }

    return false;
}

void MyDebug::CmdSetStepInto()
{
    CONTEXT context;
    MyGetContext(m_DebugEv.dwThreadId, context);

    context.EFlags |= TF_FALG;//单步标志
    MySetContext(m_DebugEv.dwThreadId, context);
}

void MyDebug::CmdSetStepOver()
{
    CONTEXT context;
    MyGetContext(m_DebugEv.dwThreadId, context);

    if (JudgeIsCall(context.Eip))
    {
        return;
    }
    context.EFlags |= TF_FALG;
    MySetContext(m_DebugEv.dwThreadId, context);
}

bool MyDebug::CmdSetBreakPoint(void * addr, bool isOnce)
{
    if (addr == 0)
    {
        MyErrorReport::ShowNormalError("断点地址不能为空");
        return false;
    }
    unsigned char code = 0xcc;

    BREAKPOINT* pBreakPoint = new BREAKPOINT;
    m_lstNormalBreakPoint.push_back(pBreakPoint);
    pBreakPoint->pAddr = addr;
    pBreakPoint->isOnce = isOnce;

    if (MyReadProcessMomory(m_DebugEv.dwProcessId, addr, &pBreakPoint->Other.cOld, 1) != 1)
    {
        MyErrorReport::ShowGetLastError("CmdSetBreakPoint->MyReadProcessMomory");
        return false;
    }

    if (MyWriteProcessMomory(m_DebugEv.dwProcessId, addr, &code, 1) != 1)
    {
        MyErrorReport::ShowGetLastError("CmdSetBreakPoint->MyWriteProcessMomory");
        return false;
    }

    return true;
}

bool MyDebug::CmdSetHardBreakPoint(void * addr, char cType, int nSize)
{
    CONTEXT context;
    MyGetContext(m_DebugEv.dwThreadId, context);

    int nDrNum = 0;
    DR7 dr7 = { 0 };
    dr7.dr7 = context.Dr7;

    for (int i = 0; i < 4; i++)
    {
        bool bFlag = true;
        for (auto item = m_lstHardBreakPoint.begin(); item != m_lstHardBreakPoint.end(); item++)
        {
            if ((*item)->Other.nDRNum == i)
            {
                bFlag = false;
                break;
            }
        }
        if (bFlag)
        {
            nDrNum = i;
            break;
        }
    }

    switch (nDrNum)
    {
        case 0:
        {
            context.Dr0 = (DWORD)addr;  //断点地址
            dr7.L0 = 1;                 //局部断点
            //断点类型
            switch (cType)
            {
                case 'e': //执行断点
                {
                    dr7.RW0 = 0;
                    break;
                }
                case 'w'://写入断点
                {
                    dr7.RW0 = 1;
                    break;
                }
                case 'a'://访问断点
                {
                    dr7.RW0 = 3;
                    break;
                }
                default:
                {
                    MyErrorReport::ShowNormalError("断点类型输入错误！");
                    return false;
                }
            }

            //断点长度
            switch (nSize)
            {
                case 1:
                {
                    dr7.LEN0 = 0;
                    break;
                }
                case 2:
                {
                    dr7.LEN0 = 1;
                    break;
                }
                case 4:
                {
                    dr7.LEN0 = 3;
                    break;
                }
                default:
                {
                    MyErrorReport::ShowNormalError("断点长度输入错误！");
                    return false;
                }  
            }
            context.Dr7 = dr7.dr7;

            break;
        }
        case 1:
        {
            context.Dr1 = (DWORD)addr;  //断点地址
            dr7.L1 = 1;                 //局部断点
                                        //断点类型
            switch (cType)
            {
            case 'e': //执行断点
            {
                dr7.RW1 = 0;
                break;
            }
            case 'w'://写入断点
            {
                dr7.RW1 = 1;
                break;
            }
            case 'a'://访问断点
            {
                dr7.RW1 = 3;
                break;
            }
            default:
            {
                MyErrorReport::ShowNormalError("断点类型输入错误！");
                return false;
            }
            }

            //断点长度
            switch (nSize)
            {
            case 1:
            {
                dr7.LEN1 = 0;
                break;
            }
            case 2:
            {
                dr7.LEN1 = 1;
                break;
            }
            case 4:
            {
                dr7.LEN1 = 3;
                break;
            }
            default:
            {
                MyErrorReport::ShowNormalError("断点长度输入错误！");
                return false;
            }
            }
            context.Dr7 = dr7.dr7;
            break;
        }
        case 2:
        {
            context.Dr2 = (DWORD)addr;  //断点地址
            dr7.L2 = 1;                 //局部断点
                                        //断点类型
            switch (cType)
            {
            case 'e': //执行断点
            {
                dr7.RW2 = 0;
                break;
            }
            case 'w'://写入断点
            {
                dr7.RW2 = 1;
                break;
            }
            case 'a'://访问断点
            {
                dr7.RW2 = 3;
                break;
            }
            default:
            {
                MyErrorReport::ShowNormalError("断点类型输入错误！");
                return false;
            }
            }

            //断点长度
            switch (nSize)
            {
            case 1:
            {
                dr7.LEN2 = 0;
                break;
            }
            case 2:
            {
                dr7.LEN2 = 1;
                break;
            }
            case 4:
            {
                dr7.LEN2 = 3;
                break;
            }
            default:
            {
                MyErrorReport::ShowNormalError("断点长度输入错误！");
                return false;
            }
            }
            context.Dr7 = dr7.dr7;
            break;
        }
        case 3:
        {
            context.Dr3 = (DWORD)addr;  //断点地址
            dr7.L3 = 1;                 //局部断点
                                        //断点类型
            switch (cType)
            {
            case 'e': //执行断点
            {
                dr7.RW3 = 0;
                break;
            }
            case 'w'://写入断点
            {
                dr7.RW3 = 1;
                break;
            }
            case 'a'://访问断点
            {
                dr7.RW3 = 3;
                break;
            }
            default:
            {
                MyErrorReport::ShowNormalError("断点类型输入错误！");
                return false;
            }
            }

            //断点长度
            switch (nSize)
            {
            case 1:
            {
                dr7.LEN3 = 0;
                break;
            }
            case 2:
            {
                dr7.LEN3 = 1;
                break;
            }
            case 4:
            {
                dr7.LEN3 = 3;
                break;
            }
            default:
            {
                MyErrorReport::ShowNormalError("断点长度输入错误！");
                return false;
            }
            }
            context.Dr7 = dr7.dr7;
            break;
        }
        break;
    }
    context.ContextFlags = CONTEXT_ALL;
    MySetContext(m_DebugEv.dwThreadId, context);

    //保存到链表
    BREAKPOINT* pBreakPoint = new BREAKPOINT;
    m_lstHardBreakPoint.push_back(pBreakPoint);
    pBreakPoint->pAddr = addr;
    pBreakPoint->cType = cType;
    pBreakPoint->nSize = nSize;
    pBreakPoint->Other.nDRNum = nDrNum;

    m_nHardBreakPointNum++;
    return true;
}

bool MyDebug::CmdSetMemoryBreakPoint(void * addr, char cType, int nSize)
{
    DWORD dwPageSize = 0;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    dwPageSize = sysInfo.dwPageSize;

    MEMORY_BASIC_INFORMATION memInfo;
    void* pPageAddr = 0;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_DebugEv.dwProcessId);
    if (hProcess == NULL)
    {
        MyErrorReport::ShowGetLastError("CmdSetMemoryBreakPoint->OpenProcess");
        return false;
    }
    DWORD dwRet = VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo));
    pPageAddr = memInfo.BaseAddress;
    
    //判断地址范围是否超过分页
    if ((int)addr + nSize >= (int)pPageAddr + dwPageSize)
    {
        MyErrorReport::ShowNormalError("当前断点分页出现跨页！");
        CloseHandle(hProcess);
        return false;
    }

    //判断该页是否设置了属性
    for (auto item = m_lstMemoryBreakPoint.begin(); item != m_lstMemoryBreakPoint.end(); item++)
    {
        if ((*item)->Other.nPage == pPageAddr)
        {
            if ((*item)->cType != cType)
            {
                MyErrorReport::ShowNormalError("当前断点分页不允许出现多种断点类型！");
                CloseHandle(hProcess);
                return false;
            }
            break;
        }
    }

    BREAKPOINT* pMemoryBreakPoint = nullptr;
    if (cType == 'r' || cType == 'w')
    {
        pMemoryBreakPoint = new BREAKPOINT;
    }
    else
    {
        MyErrorReport::ShowNormalError("断点类型输入错误！");
        CloseHandle(hProcess);
        return false;
    }

    //修改内存保护属性
    bool bFlag = false;//标记该断点所处分页是否已经被设置属性
    for (auto item = m_lstMemoryBreakPoint.begin(); item != m_lstMemoryBreakPoint.end(); item++)
    {
        if ((*item)->pAddr == addr)
        {
            pMemoryBreakPoint->dwOldType = (*item)->dwOldType;
            bFlag = true;
            break;
        }
    }

    if (!bFlag)
    {
        if (cType == 'r')
        {
            if (!VirtualProtectEx(hProcess, addr, 1, PAGE_NOACCESS, &pMemoryBreakPoint->dwOldType))
            {
                MyErrorReport::ShowGetLastError("CmdSetMemoryBreakPoint->VirtualProtectEx");
                return false;
            }
        }
        else
        {
            if (!VirtualProtectEx(hProcess, addr, 1, PAGE_EXECUTE_READ, &pMemoryBreakPoint->dwOldType))
            {
                MyErrorReport::ShowGetLastError("CmdSetMemoryBreakPoint->VirtualProtectEx");
                return false;
            }
        }
    }

    //保存到链表
    m_lstMemoryBreakPoint.push_back(pMemoryBreakPoint);
    pMemoryBreakPoint->pAddr = addr;
    pMemoryBreakPoint->cType = cType;
    pMemoryBreakPoint->nSize = nSize;
    pMemoryBreakPoint->Other.nPage = pPageAddr;
    
    CloseHandle(hProcess);
    return true;
}

bool MyDebug::CmdSetGoBreakPoint(void * addr)
{
    m_nGoAddr = (int)addr;
    unsigned char code = 0xCC;

    if (MyReadProcessMomory(m_DebugEv.dwProcessId, addr, (unsigned char*)&m_cGoCode, 1) != 1)
    {
        MyErrorReport::ShowGetLastError("CmdSetBreakPoint->MyReadProcessMomory");
        return false;
    }

    if (m_cGoCode == 0xcc)
    {
        m_nGoAddr = 0;
        return true;
    }

    if (MyWriteProcessMomory(m_DebugEv.dwProcessId, addr, &code, 1) != 1)
    {
        MyErrorReport::ShowGetLastError("CmdSetBreakPoint->MyWriteProcessMomory");
        return false;
    }

    return true;
}

BREAKPOINT * MyDebug::GetBreakPointInfo()
{
    CONTEXT context;
    MyGetContext(m_DebugEv.dwThreadId, context);

    if (m_lstNormalBreakPoint.empty())
    {
        return nullptr;
    }
    else
    {
        for (auto item = m_lstNormalBreakPoint.begin(); item != m_lstNormalBreakPoint.end(); item++)
        {
            if (context.Eip - 1 == (unsigned long)(*item)->pAddr)
            {
                return *item;
            }
        }
    }
    return nullptr;
}

int MyDebug::FindHardBreakPoint()
{
    CONTEXT context;
    MyGetContext(m_DebugEv.dwThreadId, context);

    for (auto item = m_lstHardBreakPoint.begin(); item != m_lstHardBreakPoint.end(); item++)
    {
        if (context.Eip == (DWORD)(*item)->pAddr)
        {
            return (*item)->Other.nDRNum;
        }
    }
    
    return -1;
}

bool MyDebug::GetMoDuleRange(char * szModule)
{
    int nSizeModuleName = strlen(szModule);
    if (szModule[nSizeModuleName - 3] == 'e')//exe,本进程
    {
        m_nModuleBegin = m_nTraceBegin;
        m_nModuleEnd = m_nTraceEnd;
        return true;
    }

    DWORD dwAddr = 0;
    MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)m_pTeb + 0x30, (unsigned char*)&dwAddr, sizeof(dwAddr));
    MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x0c, (unsigned char*)&dwAddr, sizeof(dwAddr));
    MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x0c, (unsigned char*)&dwAddr, sizeof(dwAddr));

    //计算进程的模块范围
    MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x18, (unsigned char*)&m_nProcBegin, sizeof(dwAddr));
    m_nProcEnd = 0;
    MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x20, (unsigned char*)&m_nProcEnd, sizeof(dwAddr));
    m_nProcEnd = m_nProcBegin + m_nProcEnd;

    while (dwAddr != 0xffffffff)
    {
        char szName[100] = { 0 };
        DWORD dwTemp = 0;
        MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x30, (unsigned char*)&dwTemp, sizeof(dwTemp));
        MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwTemp, (unsigned char*)szName, 2 * strlen(szModule));

        //转成unicode
        char szUnicodeModule[100] = { 0 };
        for (int i = 0; i < strlen(szModule); i++)
        {
            szUnicodeModule[2 * i] = szModule[i];
        }
        _wcslwr((wchar_t*)szName);
        if (wcscmp((wchar_t*)szUnicodeModule, (wchar_t*)szName) == 0)
        {
            MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x18, (unsigned char*)&m_nModuleBegin, sizeof(dwAddr));
            m_nModuleEnd = 0;
            MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr + 0x20, (unsigned char*)&m_nModuleEnd, sizeof(dwAddr));
            m_nModuleEnd = m_nModuleBegin + m_nModuleEnd;
            return true;
        }
        MyReadProcessMomory(m_DebugEv.dwProcessId, (char*)dwAddr, (unsigned char*)&dwAddr, sizeof(dwAddr));
    }
    return false;
}

void MyDebug::SetTraceInfo(int nAddr, char * pTrace)
{
    //查看该地址是否被记录
    for (auto item = m_lstTrace.begin(); item != m_lstTrace.end(); item++)
    {
        if (nAddr == (*item)->nAddr)
        {
            return;
        }
    }


    if (m_bTraceModule)//有模块跟踪
    {
        if (m_bTraceBegin)//在跟踪区
        {
            if (nAddr >= m_nModuleBegin && nAddr <= m_nModuleEnd)
            {
                //记录文件
                TRACEINFO* pTraceInfo = new TRACEINFO;
                pTraceInfo->nAddr = nAddr;
                strcpy_s(pTraceInfo->szTrace, TRACE_SIZE, pTrace);

                m_lstTrace.push_back(pTraceInfo);
                GetTraceInfo(pTrace);
            }
            else
            {
                if (nAddr > m_nTraceEnd || nAddr < m_nTraceBegin)
                {
                    m_bTraceBegin = false;
                }
            }
        }
        else
        {
            if (nAddr <= m_nTraceEnd && nAddr >= m_nTraceBegin)
            {
                m_bTraceBegin = true;
                if (nAddr >= m_nModuleBegin && nAddr <= m_nModuleEnd)
                {
                    //记录文件
                    TRACEINFO* pTraceInfo = new TRACEINFO;
                    pTraceInfo->nAddr = nAddr;
                    strcpy_s(pTraceInfo->szTrace, TRACE_SIZE, pTrace);

                    m_lstTrace.push_back(pTraceInfo);
                    GetTraceInfo(pTrace);
                }
            }
        }
    }
    else//无模块跟踪
    {
        if (m_bTraceBegin)//在跟踪区
        {
            if (nAddr < m_nTraceBegin || nAddr > m_nTraceEnd )  
            {
                m_bTraceBegin = false;
            }
            else
            {
                //记录文件
                TRACEINFO* pTraceInfo = new TRACEINFO;
                pTraceInfo->nAddr = nAddr;
                strcpy_s(pTraceInfo->szTrace, TRACE_SIZE, pTrace);

                m_lstTrace.push_back(pTraceInfo);
                GetTraceInfo(pTrace);
            }
        }
        else
        {
            if (nAddr <= m_nTraceEnd && nAddr >= m_nTraceBegin)
            {
                m_bTraceBegin = true;
                //记录文件
                TRACEINFO* pTraceInfo = new TRACEINFO;
                pTraceInfo->nAddr = nAddr;
                strcpy_s(pTraceInfo->szTrace, TRACE_SIZE, pTrace);

                m_lstTrace.push_back(pTraceInfo);
                GetTraceInfo(pTrace);
            }
        }
    }
}

void MyDebug::GetTraceInfo(char* pTrace)
{
    FILE* fpTrace = fopen("Trace.txt", "a");
    if (fpTrace == NULL)
    {
        MyErrorReport::ShowGetLastError("GetTraceInfo->fopen");
        return;
    }

    fputs(pTrace, fpTrace);
    fputc('\n', fpTrace);

    fclose(fpTrace);
}

void MyDebug::ExportScript()
{
    //打开脚本文件
    m_pFile = fopen("Record.scp", "w");
    if (m_pFile == NULL)
    {
        MyErrorReport::ShowGetLastError("ExportScript->fopen");
        return;
    }

    //遍历链表
    for (auto item = m_lstExecuteOrder.begin(); item != m_lstExecuteOrder.end(); item++)
    {
        fputs((*item)->szCMD, m_pFile);
        fputc('\n', m_pFile);

        if (strlen((*item)->szModule))
        {
            fputs((*item)->szModule, m_pFile);
        }
        else
        {
            fputs("NULL", m_pFile);
        }
        fputc('\n', m_pFile);

        fprintf(m_pFile, "%d-%d-%d-%d\n", (*item)->Other.nNum, (int)(*item)->pAddrBegin, (int)(*item)->pAddrEnd, (*item)->cType);
    }
    printf(">>脚本成功导出！\r\n");
    fclose(m_pFile);
}
//设置标记
void MyDebug::ImportScript()
{
    if (m_bIsExecuteCode)
    {
        printf(">>只能在调试开始时才能导入脚本！\r\n");
        return;
    }

    m_bExecuteRecordFile = true;

    //打开脚本文件-读
    m_pFile = fopen("Record.scp", "r");
    if (m_pFile == NULL)
    {
        MyErrorReport::ShowGetLastError("Run->fopen");
    }
}

void* MyDebug::EditMemoryData(void * pAddr)
{
    char szBuff[100] = { 0 };
    printf(">>请输入新数据：");
    gets_s(szBuff, 100);
    DWORD dwData = strtoul(szBuff, NULL, 16);

    void* pEditAddr = nullptr;
    if (pAddr)
    {
        pEditAddr = pAddr;
    }
    else
    {
        pEditAddr = m_pEditMemoryData;
    }
    //获取句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_DebugEv.dwProcessId);
    if (hProcess == NULL)
    {
        MyErrorReport::ShowGetLastError("EditMemoryData->OpenProcess");
        return false;
    }
    
    //修改内存保护属性 
    DWORD dwOldProtect = 0;
    if (!VirtualProtectEx(hProcess, pEditAddr, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtect))
    {
        MyErrorReport::ShowGetLastError("EditMemoryData->VirtualProtectEx");
    }

    DWORD dwRet = MyWriteProcessMomory(m_DebugEv.dwProcessId, pEditAddr, (unsigned char*)&dwData, sizeof(DWORD));
    if (dwRet != sizeof(DWORD))
    {
        MyErrorReport::ShowGetLastError("EditMemoryData->MyWriteProcessMomory");
    }

    //还原内存保护属性
    if (!VirtualProtectEx(hProcess, pEditAddr, sizeof(DWORD), dwOldProtect, &dwOldProtect))
    {
        MyErrorReport::ShowGetLastError("EditMemoryData->VirtualProtectEx");
    }
    CloseHandle(hProcess);
    return pEditAddr;
}

bool MyDebug::DeleteNormalBreakPoint(int nNum)
{
    int nIndex = 1;
    for (auto item = m_lstNormalBreakPoint.begin(); item != m_lstNormalBreakPoint.end(); item++)
    {
        if (nIndex == nNum)
        {
            //还原内存
            if (MyWriteProcessMomory(m_DebugEv.dwProcessId, (*item)->pAddr, &(*item)->Other.cOld, 1) != 1)
            {
                MyErrorReport::ShowGetLastError("DeleteNormalBreakPoint->MyWriteProcessMomory");
                return false;
            }

            m_lstNormalBreakPoint.erase(item);
            return true;
        }
        nIndex++;
    }

    return false;
}

bool MyDebug::DeleteHardBreakPoint(int nNum)
{
    CONTEXT context;
    MyGetContext(m_DebugEv.dwThreadId, context);

    int nIndex = 1;
    for (auto item = m_lstHardBreakPoint.begin(); item != m_lstHardBreakPoint.end(); item++)
    {
        if (nIndex == nNum)
        {
            DR7 dr7 = { 0 };
            dr7.dr7 = context.Dr7;

            //修改寄存器
            switch ((*item)->Other.nDRNum)
            {
            case 0:
            {
                dr7.L0 = 0;
                context.Dr0 = 0;
                break;
            }
            case 1:
            {
                dr7.L1 = 0;
                context.Dr1 = 0;
                break;
            }
            case 2:
            {
                dr7.L2 = 0;
                context.Dr2 = 0;
                break;
            }
            case 3:
            {
                dr7.L3 = 0;
                context.Dr3 = 0;
                break;
            }
            default:break;
            }
            context.ContextFlags = CONTEXT_ALL;
            context.Dr7 = dr7.dr7;
            MySetContext(m_DebugEv.dwThreadId, context);

            m_lstHardBreakPoint.erase(item);
            m_nHardBreakPointNum--;
            return true;
        }
        nIndex++;
    }

    return false;
}

bool MyDebug::DeleteMemoryBreakPoint(int nNum)
{
    int nIndex = 1;
    for (auto item = m_lstMemoryBreakPoint.begin(); item != m_lstMemoryBreakPoint.end(); item++)
    {
        if (nIndex == nNum)
        {
            //还原属性
            int nCount = 0;//该分页的断点个数,当该分页只剩一个断点时，才还原属性
            for (auto itemPage = m_lstMemoryBreakPoint.begin(); itemPage != m_lstMemoryBreakPoint.end(); itemPage++)
            {
                if ((*item)->Other.nPage == (*itemPage)->Other.nPage)
                {
                    nCount++;
                }
            }
            if (nCount <= 1)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_DebugEv.dwProcessId);
                if (hProcess == NULL)
                {
                    MyErrorReport::ShowGetLastError("DeleteMemoryBreakPoint->OpenProcess");
                    return false;
                }
                DWORD dwRet = 0;
                if (!VirtualProtectEx(hProcess, (*item)->pAddr, 1, (*item)->dwOldType, &dwRet))
                {
                    MyErrorReport::ShowGetLastError("DeleteMemoryBreakPoint->VirtualProtectEx");
                    return false;
                }
            }

            m_lstMemoryBreakPoint.erase(item);
            return true;
        }
        nIndex++;
    }

    return false;
}

void MyDebug::FreeList()
{
    for (auto item = m_lstTrace.begin(); item != m_lstTrace.end(); item++)
    {
        delete (*item);
    }
    for (auto item = m_lstExecuteOrder.begin(); item != m_lstExecuteOrder.end(); item++)
    {
        delete (*item);
    }
    for (auto item = m_lstNormalBreakPoint.begin(); item != m_lstNormalBreakPoint.end(); item++)
    {
        delete (*item);
    }
    for (auto item = m_lstMemoryBreakPoint.begin(); item != m_lstMemoryBreakPoint.end(); item++)
    {
        delete (*item);
    }
    for (auto item = m_lstHardBreakPoint.begin(); item != m_lstHardBreakPoint.end(); item++)
    {
        delete (*item);
    }
}



DWORD MyDebug::ExceptionDebugEvent()
{
    DWORD dwContinueStatus = DBG_CONTINUE;

    EXCEPTION_RECORD& ExceptionRecord = m_DebugEv.u.Exception.ExceptionRecord;

    switch (ExceptionRecord.ExceptionCode)
    {
    case EXCEPTION_BREAKPOINT:
        dwContinueStatus = ExceptionBreakPoint();
        break;
    case EXCEPTION_ACCESS_VIOLATION:
        dwContinueStatus = ExceptionAccess();
        break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        break;
    case EXCEPTION_SINGLE_STEP:
        dwContinueStatus = ExceptionSingleStep();
        break;
    case DBG_CONTROL_C:
        break;
    }

    return dwContinueStatus;
}

DWORD MyDebug::CreateThreadDebugEvnet()
{
    DWORD dwContinueStatus = DBG_CONTINUE;
    m_pTeb = m_DebugEv.u.CreateProcessInfo.lpThreadLocalBase;
    return dwContinueStatus;
}

DWORD MyDebug::CreateProcessDebugEvnet()
{
    DWORD dwContinueStatus = DBG_CONTINUE;

    //获取TEB
    m_pTeb = m_DebugEv.u.CreateProcessInfo.lpThreadLocalBase;


    //设置入口断点
    CmdSetBreakPoint(m_DebugEv.u.CreateProcessInfo.lpStartAddress, true);
    m_pShowMemory = m_DebugEv.u.CreateProcessInfo.lpStartAddress;
    m_pEditMemoryData = m_pShowMemory;

    return dwContinueStatus;
}

DWORD MyDebug::ExitThreadDebugEvnet()
{
    DWORD dwContinueStatus = DBG_CONTINUE;
    //printf("ExitThreadDebugEvnet tid:%d ExitCode:%d\n",
    //    m_DebugEv.dwThreadId,
    //    m_DebugEv.u.ExitThread.dwExitCode);
    return dwContinueStatus;
}

DWORD MyDebug::ExitProcessDebugEvnet()
{
    DWORD dwContinueStatus = DBG_CONTINUE;
    //printf("ExitProcessDebugEvnet pid:%d ExitCode:%d\n",
    //    m_DebugEv.dwProcessId,
    //    m_DebugEv.u.ExitProcess.dwExitCode);

    //结束调试,主进程结束
    if (m_DebugEv.dwProcessId == m_pi.dwProcessId)
    {
        exit(0);
    }
        
    return dwContinueStatus;
}

DWORD MyDebug::LoadDllDebugEvnet()
{
    DWORD dwContinueStatus = DBG_CONTINUE;
    wchar_t path[MAX_PATH];
    SIZE_T NumberOfBytesRead;

    path[0] = '\0';
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_DebugEv.dwProcessId);
    if (hProcess == NULL)
    {
        MyErrorReport::ShowGetLastError("LoadDllDebugEvnet->OpenProcess");
        return false;
    }
    if (ReadProcessMemory(hProcess,
        m_DebugEv.u.LoadDll.lpImageName,
        path,
        sizeof(int*),
        &NumberOfBytesRead))
    {
        ReadProcessMemory(hProcess,
            *(int**)path,
            path,
            sizeof(path),
            &NumberOfBytesRead);
    }

    CloseHandle(hProcess);

    //if (m_DebugEv.u.LoadDll.fUnicode == 1) {
    //    wprintf(L"LoadDllDebugEvnet base=%p name:%s\n",
    //        m_DebugEv.u.LoadDll.lpBaseOfDll,
    //        path);
    //}

    return dwContinueStatus;
}

DWORD MyDebug::UnloadDllDebugEvnet()
{
    DWORD dwContinueStatus = DBG_CONTINUE;
    //printf("UnloadDllDebugEvnet Base=%p\n",
    //    m_DebugEv.u.UnloadDll.lpBaseOfDll);
    return dwContinueStatus;
}

DWORD MyDebug::OutputStringDebugEvnet()
{
    DWORD dwContinueStatus = DBG_CONTINUE;
    //if (m_DebugEv.u.DebugString.fUnicode == 1) {
    //    wprintf(L"OutputStringDebugEvnet length:%d %s\n",
    //        m_DebugEv.u.DebugString.nDebugStringLength,
    //        m_DebugEv.u.DebugString.lpDebugStringData);
    //}
    //else {
    //    printf("OutputStringDebugEvnet length:%d %s\n",
    //        m_DebugEv.u.DebugString.nDebugStringLength,
    //        m_DebugEv.u.DebugString.lpDebugStringData);
    //}

    return dwContinueStatus;
}

DWORD MyDebug::RipDebugEvnet()
{
    DWORD dwContinueStatus = DBG_CONTINUE;
    //printf("RipDebugEvnet\n");
    return dwContinueStatus;
}


