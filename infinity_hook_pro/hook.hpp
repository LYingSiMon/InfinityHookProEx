#pragma once
#include <ntifs.h>

// 回调函数
typedef void(__fastcall* INFINITYHOOKCALLBACK)(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction);

// 初始化数据
bool IfhInitialize2(INFINITYHOOKCALLBACK fptr);

// 反初始化数据
bool IfhRelease2();