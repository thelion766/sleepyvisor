#include "vmx.h"



extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
	if (!vmx::is_vmx_supported())
		return 0x1;

	if (!vmx::is_vmx_enabled())
		vmx::enable_vmx();

	if (!vmx::virtualise_all_cores())
		return 0x1;

	//vmx::devirtualise_all_cores();

	return 0x0;
}