#include "MyErrorReport.h"

MyErrorReport::MyErrorReport()
{
}

MyErrorReport::~MyErrorReport()
{
}

void MyErrorReport::ShowGetLastError(char * pError)
{
    LPVOID lpMsgBuf;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
        (LPTSTR)&lpMsgBuf,
        0,
        NULL
    );

    printf(">>%s:%s", pError, lpMsgBuf);

    LocalFree(lpMsgBuf);
}

void MyErrorReport::ShowNormalError(char * pError)
{
    printf(">>ERROR : %s\r\n", pError);
}
