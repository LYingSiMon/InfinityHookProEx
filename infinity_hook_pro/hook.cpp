#include "hook.hpp"
#include "utils.hpp"

#pragma warning(disable : 4201)

// ==================================
// 结构定义
// ==================================

/* 微软官方文档定义
*   https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header*/
typedef struct _WNODE_HEADER
{
	ULONG BufferSize;
	ULONG ProviderId;
	union {
		ULONG64 HistoricalContext;
		struct {
			ULONG Version;
			ULONG Linkage;
		};
	};
	union {
		HANDLE KernelHandle;
		LARGE_INTEGER TimeStamp;
	};
	GUID Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER, * PWNODE_HEADER;

/* 微软文档定义
*   https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties*/
typedef struct _EVENT_TRACE_PROPERTIES
{
	WNODE_HEADER Wnode;
	ULONG BufferSize;
	ULONG MinimumBuffers;
	ULONG MaximumBuffers;
	ULONG MaximumFileSize;
	ULONG LogFileMode;
	ULONG FlushTimer;
	ULONG EnableFlags;
	union {
		LONG AgeLimit;
		LONG FlushThreshold;
	} DUMMYUNIONNAME;
	ULONG NumberOfBuffers;
	ULONG FreeBuffers;
	ULONG EventsLost;
	ULONG BuffersWritten;
	ULONG LogBuffersLost;
	ULONG RealTimeBuffersLost;
	HANDLE LoggerThreadId;
	ULONG LogFileNameOffset;
	ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
	ULONG64 Unknown[3];
	UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

typedef enum _trace_type
{
	start_trace = 1,
	stop_trace = 2,
	query_trace = 3,
	syscall_trace = 4,
	flush_trace = 5
}trace_type;


// ==================================
// 全局变量
// ==================================

extern "C"
{
	ULONG_PTR halCounterQueryRoutine;								// 等于 1 时，hook 之前的函数
	VOID keQueryPerformanceCounterHook(ULONG_PTR* pStack);			// 等于 1 时，hook 函数中用来回溯调用栈
	VOID checkLogger();												// 等于 1 时，hook 函数
}

GUID g_ckcl_session_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };
INFINITYHOOKCALLBACK g_fptr = nullptr;								// syscall 回调函数
unsigned long g_build_number = 0;									// 系统版本号
void* g_EtwpDebuggerData = nullptr;
void* g_CkclWmiLoggerContext = nullptr;
void* g_syscall_table = nullptr;									// ssdt 基地址
void** g_EtwpDebuggerDataSilo = nullptr;
void** g_GetCpuClock = nullptr;
unsigned long long h_original_GetCpuClock = 0;						// 原始的 GetCpuClock 值
unsigned long long g_HvlpReferenceTscPage = 0;
unsigned long long g_HvlGetQpcBias = 0;								// 18363 以上版本，要 hook 的位置
typedef __int64 (*fptr_HvlGetQpcBias)();
fptr_HvlGetQpcBias g_original_HvlGetQpcBias = nullptr;				// 18363 以上版本，要 hook 的位置的原始值

// ==================================
// 函数实现
// ==================================

// 注册 etw
NTSTATUS modify_trace_settings(trace_type type)
{
	const unsigned long tag = 'VMON';

	// 申请内存
	CKCL_TRACE_PROPERTIES* property = (CKCL_TRACE_PROPERTIES*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, tag);
	if (!property)
	{
		KdPrintEx((0, 0, "[%s] allocate ckcl trace propertice struct fail \n", __FUNCTION__));
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	wchar_t* provider_name = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(wchar_t), tag);
	if (!provider_name)
	{
		KdPrintEx((0, 0, "[%s] allocate provider name fail \n", __FUNCTION__));
		ExFreePoolWithTag(property, tag);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	// 初始化内存
	RtlZeroMemory(property, PAGE_SIZE);
	RtlZeroMemory(provider_name, 256 * sizeof(wchar_t));

	// 名称赋值
	RtlCopyMemory(provider_name, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
	RtlInitUnicodeString(&property->ProviderName, (const wchar_t*)provider_name);

	// 结构体填充
	property->Wnode.BufferSize = PAGE_SIZE;
	property->Wnode.Flags = 0x00020000;
	property->Wnode.Guid = g_ckcl_session_guid;
	property->Wnode.ClientContext = 3;
	property->BufferSize = sizeof(unsigned long);
	property->MinimumBuffers = 2;
	property->MaximumBuffers = 2;
	property->LogFileMode = 0x00000400;

	// 注册 etw
	unsigned long length = 0;
	if (type == trace_type::syscall_trace)
	{
		property->EnableFlags = 0x00000080;
	}
	NTSTATUS status = NtTraceControl(type, property, PAGE_SIZE, property, PAGE_SIZE, &length);

	// 释放内存空间
	ExFreePoolWithTag(provider_name, tag);
	ExFreePoolWithTag(property, tag);

	return status;
}

// 原作者堆栈回溯函数（这里只用它处理 1909 以前的版本）
unsigned long long self_get_cpu_clock()
{
	// 放过内核模式的调用
	if (ExGetPreviousMode() == KernelMode)
	{
		// 调用原函数
		return __rdtsc();
	}

	// 拿到当前线程
	PKTHREAD current_thread = (PKTHREAD)__readgsqword(0x188);

	// 不同版本不同偏移
	unsigned int call_index = 0;
	if (g_build_number <= 7601)
	{
		call_index = *(unsigned int*)((unsigned long long)current_thread + 0x1f8);
	}
	else
	{
		call_index = *(unsigned int*)((unsigned long long)current_thread + 0x80);
	}

	// 拿到当前栈底和栈顶
	void** stack_max = (void**)__readgsqword(0x1a8);
	void** stack_frame = (void**)_AddressOfReturnAddress();

	// 开始查找当前栈中的ssdt调用
	for (void** stack_current = stack_max; stack_current > stack_frame; --stack_current)
	{
		/* 栈中ssdt调用特征,分别是
		*   mov [rsp+48h+var_20], 501802h
		*   mov r9d, 0F33h
		*/

		// 第一个特征值检查
		unsigned long* l_value = (unsigned long*)stack_current;
		if (*l_value != 0x501802)
		{
			continue;
		}

		// 这里为什么减?配合寻找第二个特征值啊
		--stack_current;

		// 第二个特征值检查
		unsigned short* s_value = (unsigned short*)stack_current;
		if (*s_value != 0xF33)
		{
			continue;
		}

		// 特征值匹配成功,再倒过来查找
		for (; stack_current < stack_max; ++stack_current)
		{
			// 不在 ssdt 表内的 pass
			unsigned long long* ull_value = (unsigned long long*)stack_current;
			if (!(PAGE_ALIGN(*ull_value) >= g_syscall_table && PAGE_ALIGN(*ull_value) < (void*)((unsigned long long)g_syscall_table + (PAGE_SIZE * 2))))
			{
				continue;
			}

			// 拿到系统调用函数的地址
			void** system_call_function = &stack_current[9];

			// 替换为我们的函数
			if (g_fptr)
			{
				g_fptr(call_index, system_call_function);
			}

			break;
		}

		break;
	}

	// 调用原函数
	return __rdtsc();
}

#if 0
// 原作者 hook 函数（已经用不到了）
EXTERN_C __int64 self_hvl_get_qpc_bias()
{
	// 我们的过滤函数
	self_get_cpu_clock();

	// 这里是真正HvlGetQpcBias做的事情
	return *((unsigned long long*)(*((unsigned long long*)g_HvlpReferenceTscPage)) + 3);
}
#endif

bool start()
{
	//__debugbreak();

	if (!g_fptr)
	{
		return false;
	}

	// 注册 etw
	if (!NT_SUCCESS(modify_trace_settings(syscall_trace)))
	{
		if (!NT_SUCCESS(modify_trace_settings(start_trace)))
		{
			KdPrintEx((0, 0, "[%s] start ckcl fail \n", __FUNCTION__));
			return false;
		}
		if (!NT_SUCCESS(modify_trace_settings(syscall_trace)))
		{
			KdPrintEx((0, 0, "[%s] syscall ckcl fail \n", __FUNCTION__));
			return false;
		}
	}

	/* 这里我们区分一下系统版本
	*   从Win7到Win10 1909,g_GetCpuClock是一个函数,往后的版本是一个数值了
	*   大于3 抛异常
	*   等于3 用rdtsc
	*   等于2 用off_140C00A30
	*   等于1 用KeQueryPerformanceCounter
	*   等于0 用RtlGetSystemTimePrecise
	*   参考网址:
	*		https://www.freebuf.com/articles/system/278857.html
	*		https://www.anquanke.com/post/id/206288
	*/
	if (g_build_number <= 18363)
	{
		// 直接修改函数指针
		KdPrintEx((0, 0, "[%s] verion <= 18363 ,direct modify GetCpuClock:0x%p \n",__FUNCTION__, g_GetCpuClock));

		*g_GetCpuClock = self_get_cpu_clock;

		KdPrintEx((0, 0, "[%s] after modify 0x%p\n", __FUNCTION__, *g_GetCpuClock));
	}
	else
	{
		// 保存 GetCpuClock 原始值
		h_original_GetCpuClock = (unsigned long long)(*g_GetCpuClock);
		KdPrintEx((0, 0, "[%s] verion > 18363 , GetCpuClock index:%lld \n", __FUNCTION__, h_original_GetCpuClock));

		//	原作者将 GetCpuClock 设置为 2，但这样做在物理机上无效
		*g_GetCpuClock = (void*)1;
		KdPrintEx((0, 0, "[%s] modify GetCpuClock:%p \n", __FUNCTION__, *g_GetCpuClock));

#if 0
		// 等于 2 时的挂钩逻辑
		g_original_HvlGetQpcBias = (fptr_HvlGetQpcBias)(*((unsigned long long*)g_HvlGetQpcBias));
		*((unsigned long long*)g_HvlGetQpcBias) = (unsigned long long)self_hvl_get_qpc_bias;
		KdPrintEx((0, 0, "[%s] HvlGetQpcBias modify success:%p \n", __FUNCTION__, self_hvl_get_qpc_bias));
#else
		// 等于 1 时的挂钩逻辑
		*((unsigned long long*)g_HvlGetQpcBias) = (unsigned long long)checkLogger;
		KdPrintEx((0, 0, "[%s] HvlGetQpcBias modify success:%p \n", __FUNCTION__, checkLogger));
#endif
	}

	return true;
}

bool stop()
{
	// 反注册 etw
	bool result = NT_SUCCESS(modify_trace_settings(stop_trace)) && NT_SUCCESS(modify_trace_settings(start_trace));

	if (g_build_number > 18363)
	{
#if 0
		// 等于 2 时的恢复挂钩
		* ((unsigned long long*)g_HvlGetQpcBias) = (unsigned long long)g_original_HvlGetQpcBias;
#else
		// 等于 1 时的恢复挂钩
		* ((unsigned long long*)g_HvlGetQpcBias) = (unsigned long long)halCounterQueryRoutine;
#endif
		// 恢复 GetCpuClock
		*g_GetCpuClock = (void*)h_original_GetCpuClock;
	}

	return result;
}

bool IfhInitialize2(INFINITYHOOKCALLBACK fptr)
{
	//__debugbreak();

	if (!fptr)
	{
		return false;
	}
	
	// 保存 callback 函数地址
	g_fptr = fptr;
	KdPrintEx((0, 0, "[%s] callback:0x%p \n", __FUNCTION__, g_fptr));

	// 获取系统版本号
	g_build_number = k_utils::get_system_build_number();
	if (!g_build_number)
	{
		return false;
	}
	KdPrintEx((0, 0, "[%s] system version number:%ld \n", __FUNCTION__, g_build_number));

	// 获取 ntoskrnl 基址
	unsigned long long ntoskrnl = k_utils::get_module_address("ntoskrnl.exe", nullptr);
	if (!ntoskrnl)
	{
		return false;
	}
	KdPrintEx((0, 0, "[%s] ntoskrnl base address:0x%llX \n", __FUNCTION__, ntoskrnl));

	// 定位 EtwpDebuggerData
	unsigned long long EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
	if (!EtwpDebuggerData)
	{
		EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".data");
	}
	if (!EtwpDebuggerData)
	{
		EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".rdata");
	}
	if (!EtwpDebuggerData)
	{
		return false;
	}
	KdPrintEx((0, 0, "[%s] EtwpDebuggerData:0x%llX \n", __FUNCTION__, EtwpDebuggerData));
	g_EtwpDebuggerData = (void*)EtwpDebuggerData;

	// 定位 EtwpDebuggerDataSilo
	g_EtwpDebuggerDataSilo = *(void***)((unsigned long long)g_EtwpDebuggerData + 0x10);
	if (!g_EtwpDebuggerDataSilo)
	{
		return false;
	}
	KdPrintEx((0, 0, "[%s] EtwpDebuggerDataSilo:0x%p \n", __FUNCTION__, g_EtwpDebuggerDataSilo));

	// 定位 CkclWmiLoggerContext
	g_CkclWmiLoggerContext = g_EtwpDebuggerDataSilo[0x2];
	if (!g_CkclWmiLoggerContext)
	{
		return false;
	}
	KdPrintEx((0, 0, "[%s] CkclWmiLoggerContext:0x%p \n", __FUNCTION__, g_CkclWmiLoggerContext));

	// 定位 GetCpuClock（Win7、Win11 都是偏移 0x18, 其它的是 0x28）
	if (g_build_number <= 7601 || g_build_number == 22000)
	{
		g_GetCpuClock = (void**)((unsigned long long)g_CkclWmiLoggerContext + 0x18);
	}
	else
	{
		g_GetCpuClock = (void**)((unsigned long long)g_CkclWmiLoggerContext + 0x28);
	}
	if (!MmIsAddressValid(g_GetCpuClock))
	{
		return false;
	}
	KdPrintEx((0, 0, "[%s] original GetCpuClock:0x%p \n", __FUNCTION__, *g_GetCpuClock));

	// 定位 ssdt
	g_syscall_table = PAGE_ALIGN(k_utils::get_syscall_entry(ntoskrnl));
	if (!g_syscall_table)
	{
		return false;
	}
	KdPrintEx((0, 0, "[%s] ssdt:0x%p \n", __FUNCTION__, g_syscall_table));

	// 大于 18363 版本要做额外的工作
	if (g_build_number > 18363)
	{
#if 0
		// 等于 2 时

		/* 定位
		* nt!HvlGetReferenceTimeUsingTscPage+0x3e:
			488b059b1b9700		mov rax,qword ptr [nt!HvlpReferenceTscPage]
			488b4008			mov rax,qword ptr [rax+8]
			488b0d901b9700		mov rcx,qword ptr [nt!HvlpReferenceTscPage]
			48f7e2				mul rax,rdx
		*/
		unsigned long long address2 = k_utils::find_pattern_image(ntoskrnl,
			"\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\x40\x00\x48\x8b\x0d\x00\x00\x00\x00\x48\xf7\xe2",
			"xxx????xxx?xxx????xxx");
		if (!address2)
		{
			return false;
		}

		// 计算 HvlpReferenceTscPage 地址
		g_HvlpReferenceTscPage = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(address2) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address2) + 3));
		if (!g_HvlpReferenceTscPage)
		{
			return false;
		}
		KdPrintEx((0, 0, "[%s] hvlp reference tsc page is 0x%llX \n", __FUNCTION__, g_HvlpReferenceTscPage));

		/* 定位 HvlGetQpcBias（HalpEnlightenment+0x178）
		*  参考:https://www.freebuf.com/articles/system/278857.html
		* nt!HalpTimerQueryHostPerformanceCounter+0x22:
			488b05ef8f7900		mov     rax,qword ptr [nt!HalpEnlightenment+0x178]
			4885c0				test    rax,rax
			7428				je      nt!HalpTimerQueryHostPerformanceCounter+0x56
			48833d928e790000	cmp     qword ptr [nt!HalpEnlightenment+0x28],0
			741e				je      nt!HalpTimerQueryHostPerformanceCounter+0x56
			e803d5f4ff			call    nt!guard_dispatch_icall							<<< 调用 rax 中的函数，HalpEnlightenment+0x178
		*/
		address2 = k_utils::find_pattern_image(ntoskrnl,
			"\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x48\x83\x3d\x00\x00\x00\x00\x00\x74",
			"xxx????xxxx?xxx?????x");
		if (!address2)
		{
			address2 = k_utils::find_pattern_image(ntoskrnl,
				"\x48\x8b\x05\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x48\x03\xd8\x48\x89\x1f",
				"xxx????x????xxxxxx");
		}
		if (!address2)
		{
			return false;
		}

		// 保存 hook 地址
		g_HvlGetQpcBias = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(address) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 3));

#else
		// 等于 1 时

		/* 定位特征
			nt!KeQueryPerformanceCounter:
			fffff801`68485190 48895c2420      mov     qword ptr [rsp+20h],rbx
			fffff801`68485195 56              push    rsi
			fffff801`68485196 4883ec20        sub     rsp,20h
			fffff801`6848519a 48897c2430      mov     qword ptr [rsp+30h],rdi
			fffff801`6848519f 488bf1          mov     rsi,rcx
			fffff801`684851a2 488b3d276c9c00  mov     rdi,qword ptr [nt!HalpPerformanceCounter (fffff801`68e4bdd0)]			<<< 获取这条指令的地址
			fffff801`684851a9 4c89742440      mov     qword ptr [rsp+40h],r14
			fffff801`684851ae 83bfe400000005  cmp     dword ptr [rdi+0E4h],5
			fffff801`684851b5 0f8581000000    jne     nt!KeQueryPerformanceCounter+0xac (fffff801`6848523c)
			fffff801`684851bb 48833d1d6d9c0000 cmp     qword ptr [nt!HalpTimerReferencePage (fffff801`68e4bee0)],0
			fffff801`684851c3 48c744243880969800 mov   qword ptr [rsp+38h],989680h
			fffff801`684851cc 0f842e181900    je      nt!KeQueryPerformanceCounter+0x191870 (fffff801`68616a00)
			fffff801`684851d2 f787e000000000000100 test dword ptr [rdi+0E0h],10000h
			fffff801`684851dc 0f8536191900    jne     nt!KeQueryPerformanceCounter+0x191988 (fffff801`68616b18)
			fffff801`684851e2 488b4f48        mov     rcx,qword ptr [rdi+48h]
			fffff801`684851e6 488b4770        mov     rax,qword ptr [rdi+70h]
			fffff801`684851ea e8d1ca1700      call    nt!guard_dispatch_icall (fffff801`68601cc0)							<<< 这个 call 调用的是 rax 指向的函数
			fffff801`684851ef 488bc8          mov     rcx,rax
			fffff801`684851f2 49b8b803000080f7ffff mov r8,0FFFFF780000003B8h
			fffff801`684851fc 488b05dd6c9c00  mov     rax,qword ptr [nt!HalpTimerReferencePage (fffff801`68e4bee0)]
			fffff801`68485203 488b4008        mov     rax,qword ptr [rax+8]
			fffff801`68485207 4d8b00          mov     r8,qword ptr [r8]
			fffff801`6848520a 48f7e1          mul     rax,rcx
			fffff801`6848520d 498d0410        lea     rax,[r8+rdx]
			fffff801`68485211 488b0db06b9c00  mov     rcx,qword ptr [nt!HalpOriginalPerformanceCounter (fffff801`68e4bdc8)]
			fffff801`68485218 4c8b742440      mov     r14,qword ptr [rsp+40h]
			fffff801`6848521d 483bf9          cmp     rdi,rcx
			fffff801`68485220 488b7c2430      mov     rdi,qword ptr [rsp+30h]
			fffff801`68485225 0f85db000000    jne     nt!KeQueryPerformanceCounter+0x176 (fffff801`68485306)
			fffff801`6848522b 4885f6          test    rsi,rsi
			fffff801`6848522e 7545            jne     nt!KeQueryPerformanceCounter+0xe5 (fffff801`68485275)
			fffff801`68485230 488b5c2448      mov     rbx,qword ptr [rsp+48h]
			fffff801`68485235 4883c420        add     rsp,20h
			fffff801`68485239 5e              pop     rsi
			fffff801`6848523a c3              ret
			fffff801`6848523b cc              int     3
		*/

		unsigned long long address1 = k_utils::find_pattern_image(ntoskrnl,
			"\x48\x8b\x3d\x00\x00\x00\x00\x4c\x89\x74\x24\x40\x83\xbf\xe4\x00\x00\x00\x05",
			"xxx????xxxxxxxxxxxx");
		if (!address1)
		{
			address1 = k_utils::find_pattern_image(ntoskrnl,
				"\x48\x8b\x3d\x00\x00\x00\x00\x4c\x8b\xf1\xbd\x80\x96\x98\x00\x83\xbf\xe4\x00\x00\x00\x05",
				"xxx????xxxxxxxxxxxxxxx");
		}
		if (!address1)
		{
			return false;
		}

		// [HalpPerformanceCounter]+0x70 这个地址里存放了要替换的函数指针
		g_HvlGetQpcBias = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(address1) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address1) + 3));
		if (!g_HvlGetQpcBias)
		{
			return false;
		}

		// 保存 hook 地址
		g_HvlGetQpcBias = *(ULONG64*)g_HvlGetQpcBias + 0x70;
		KdPrintEx((0, 0, "[%s] HvlGetQpcBias:0x%llX \n", __FUNCTION__, g_HvlGetQpcBias));

		// 保存 hook 之前的函数
		halCounterQueryRoutine = *(ULONG64*)g_HvlGetQpcBias;
#endif
						
	}

	start();

	return true;
}

bool IfhRelease2()
{
	return stop();
}

VOID keQueryPerformanceCounterHook(ULONG_PTR* pStack)
{
	// pStack 参数用不到
	UNREFERENCED_PARAMETER(pStack);

	// 内核层的调用不处理
	if (ExGetPreviousMode() == KernelMode)
	{
		return;
	}

	// 拿到当前线程 KTHREAD
	PKTHREAD current_thread = KeGetCurrentThread();

	// 不同版本不同偏移 KTHREAD->SystemCallNumber
	UINT call_index = 0;
	if (g_build_number <= 7601)
	{
		call_index = *(unsigned int*)((unsigned long long)current_thread + 0x1f8);
	}
	else
	{
		call_index = *(unsigned int*)((unsigned long long)current_thread + 0x80);
	}

	// 拿到当前栈顶（KPCR->Prcb.RspBase,其中 gs:[0] = KPCR）
	void** stack = (void**)__readgsqword(0x1a8);

	// 搜索全部堆栈会导致卡死，这里搜前 0x100 范围
	for (void** stack_current = stack; stack_current > stack - 0x100; --stack_current)
	{
		/* 栈中ssdt调用特征,分别是
		*   mov [rsp+48h+var_20], 501802h
		*   mov r9d, 0F33h
		*/
		// 第一个特征值检查
		unsigned long* l_value = (unsigned long*)stack_current;
		if (*l_value != 0x501802)
		{
			continue;
		}

		// 第二个特征值检查
		--stack_current;
		unsigned short* s_value = (unsigned short*)stack_current;
		if (*s_value != 0xF33)
		{
			continue;
		}

		// 特征值匹配成功，再倒过来查找
		for (; stack_current < stack; ++stack_current)
		{
			// 检查是否在 ssdt 表内
			ULONG_PTR* ull_value = (ULONG_PTR*)stack_current;
			if (!(PAGE_ALIGN(*ull_value) >= g_syscall_table && PAGE_ALIGN(*ull_value) < (void*)((unsigned long long)g_syscall_table + (PAGE_SIZE * 2))))
			{
				continue;
			}

			// 获取系统调用函数地址
			PVOID* system_call_function = &stack_current[9];

			// 调用回调函数
			if (g_fptr)
			{
				g_fptr(call_index, system_call_function);
			}

			break;
		}

		break;
	}
		
	return;
}
