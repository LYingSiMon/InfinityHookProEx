#include "hook.hpp"

typedef NTSTATUS(NTAPI* PNtCreateFile)(
	OUT PHANDLE            FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK   IoStatusBlock,
	IN PLARGE_INTEGER     AllocationSize OPTIONAL,
	IN ULONG              FileAttributes,
	IN ULONG              ShareAccess,
	IN ULONG              CreateDisposition,
	IN ULONG              CreateOptions,
	IN PVOID              EaBuffer,
	IN ULONG              EaLength);
PNtCreateFile g_NtCreateFile = 0;

NTSTATUS NTAPI MyNtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, 
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes, 
	ULONG ShareAccess,
	ULONG CreateDisposition, 
	ULONG CreateOptions,
	PVOID EaBuffer, 
	ULONG EaLength)
{
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		wchar_t* name = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t),'xiq2');
		if (name)
		{
			RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
			KdPrintEx((0, 0, "[%s] name:%wZ \n", __FUNCTION__, ObjectAttributes->ObjectName));

			if (wcsstr(name, L"tips.txt"))
			{
				ExFreePool(name);
				return STATUS_ACCESS_DENIED;
			}

			ExFreePool(name);
		}
	}

	return NtCreateFile(
		FileHandle, 
		DesiredAccess, 
		ObjectAttributes,
		IoStatusBlock, 
		AllocationSize, 
		FileAttributes, 
		ShareAccess,
		CreateDisposition, 
		CreateOptions, 
		EaBuffer, 
		EaLength);
}

void __fastcall call_back(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction)
{
	UNREFERENCED_PARAMETER(SystemCallIndex);

	if (*SystemCallFunction == NtCreateFile)
	{
		*SystemCallFunction = MyNtCreateFile;
	}
}

VOID DriverUnload(PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);

	KdPrintEx((0, 0, "[%s] \n", __FUNCTION__));

	IfhRelease2();
}

EXTERN_C
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT driver,
	PUNICODE_STRING registe)
{

	UNREFERENCED_PARAMETER(registe);

	KdPrintEx((0, 0, "[%s] \n", __FUNCTION__));

	driver->DriverUnload = DriverUnload;

	// ≥ı ºªØ≤¢π“π≥
	IfhInitialize2(call_back);

	return STATUS_SUCCESS;
}