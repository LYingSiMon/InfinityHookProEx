#pragma once
#include <ntifs.h>

// �ص�����
typedef void(__fastcall* INFINITYHOOKCALLBACK)(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction);

// ��ʼ������
bool IfhInitialize2(INFINITYHOOKCALLBACK fptr);

// ����ʼ������
bool IfhRelease2();