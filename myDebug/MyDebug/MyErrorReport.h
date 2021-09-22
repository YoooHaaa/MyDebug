#pragma once
#include <windows.h>
#include <stdio.h>

class MyErrorReport
{
public:
    MyErrorReport();
    ~MyErrorReport();

    static void ShowGetLastError(char* pError);
    static void ShowNormalError(char* pError);
};