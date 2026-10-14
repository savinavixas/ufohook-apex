#ifndef KDLIBMODE

#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>

#include "kdmapper.hpp"
#include "utils.hpp"
#include "intel_driver.hpp"

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (intel_driver::hDevice)
		intel_driver::Unload();

	return EXCEPTION_EXECUTE_HANDLER;
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

	if (kdmUtils::IsHvciWithBlocklistActive())
		return -2;

	bool free = paramExists(argc, argv, L"free") > 0;
	bool poolMode = paramExists(argc, argv, L"pool") > 0;
	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;
	bool copyHeader = paramExists(argc, argv, L"copy-header") > 0;

	std::wstring vulnPath = getParamValue(argc, argv, L"vuln");

	if (vulnPath.empty()) {
		wchar_t exePath[MAX_PATH];
		GetModuleFileNameW(nullptr, exePath, MAX_PATH);
		std::filesystem::path exeDir = std::filesystem::path(exePath).parent_path();
		vulnPath = (exeDir / ENCW(L"WDTKernel.sys")).wstring();
	}

	if (!std::filesystem::exists(vulnPath))
		return -1;

	intel_driver::vulnerableDriverPath = vulnPath;

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
		return -1;
	}

	kdmapper::AllocationMode mode = poolMode
		? kdmapper::AllocationMode::AllocatePool
		: kdmapper::AllocationMode::AllocateIndependentPages;

	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(raw_image.data(), 0, 0, free, !copyHeader, mode, passAllocationPtr, nullptr, &exitCode)) {
		intel_driver::Unload();
		return -1;
	}

	if (!NT_SUCCESS(intel_driver::Unload()))
		return -1;

	return 0;
}

#endif
