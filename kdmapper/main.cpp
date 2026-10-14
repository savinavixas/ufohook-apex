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
	if (vdrv::hDevice)
		vdrv::Unload();

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
	bool overlayMode = paramExists(argc, argv, L"overlay") > 0;
	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;
	bool copyHeader = paramExists(argc, argv, L"copy-header") > 0;

	std::wstring preferredHostW = getParamValue(argc, argv, L"host");
	std::string preferredHost;
	if (!preferredHostW.empty()) {
		int wlen = (int)preferredHostW.size();
		int alen = WideCharToMultiByte(CP_ACP, 0, preferredHostW.c_str(), wlen, nullptr, 0, nullptr, nullptr);
		if (alen > 0) {
			preferredHost.resize(alen);
			WideCharToMultiByte(CP_ACP, 0, preferredHostW.c_str(), wlen, &preferredHost[0], alen, nullptr, nullptr);
		}
	}

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
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

	if (!NT_SUCCESS(vdrv::Load()))
		return -1;

	std::vector<uint8_t> raw_image = { 0 };
	if (!kdmUtils::ReadFileToMemory(driver_path, &raw_image)) {
		vdrv::Unload();
		return -1;
	}

	kdmapper::AllocationMode mode;
	if (overlayMode)
		mode = kdmapper::AllocationMode::OverlayIntoHostDriver;
	else if (poolMode)
		mode = kdmapper::AllocationMode::AllocatePool;
	else
		mode = kdmapper::AllocationMode::AllocateIndependentPages;

	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(raw_image.data(), 0, 0, free, !copyHeader, mode, passAllocationPtr, nullptr, &exitCode, preferredHost)) {
		vdrv::Unload();
		return -1;
	}

	if (!NT_SUCCESS(vdrv::Unload()))
		return -1;

	return 0;
}

#endif
