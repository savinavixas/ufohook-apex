#include "service.hpp"
#include <Windows.h>
#include <string>
#include <iostream>

#include "utils.hpp"
#include "nt.hpp"

NTSTATUS service::RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName) {
	const static DWORD ServiceTypeKernel = 1;
	const static DWORD StartType = 3;
	const static DWORD ErrorControl = 1;
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice);
	if (status != ERROR_SUCCESS)
		return STATUS_REGISTRY_IO_FAILED;

	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return STATUS_REGISTRY_IO_FAILED;
	}

	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return STATUS_REGISTRY_IO_FAILED;
	}

	RegSetKeyValueW(dservice, NULL, L"Start", REG_DWORD, &StartType, sizeof(DWORD));
	RegSetKeyValueW(dservice, NULL, L"ErrorControl", REG_DWORD, &ErrorControl, sizeof(DWORD));

	static const wchar_t* display_options[] = {
		L"Hardware Diagnostics Agent",
		L"System Telemetry Collector",
		L"Device Health Monitor",
		L"Hardware Resource Manager",
		L"Peripheral Status Reporter",
		L"System Component Service"
	};
	HCRYPTPROV hProv2 = 0;
	ULONG rnd = 0;
	if (CryptAcquireContextW(&hProv2, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		CryptGenRandom(hProv2, sizeof(rnd), reinterpret_cast<BYTE*>(&rnd));
		CryptReleaseContext(hProv2, 0);
	}
	const wchar_t* displayName = display_options[rnd % (sizeof(display_options) / sizeof(display_options[0]))];
	DWORD dnLen = (DWORD)((wcslen(displayName) + 1) * sizeof(wchar_t));
	RegSetKeyValueW(dservice, NULL, L"DisplayName", REG_SZ, displayName, dnLen);

	static const wchar_t* desc_options[] = {
		L"Provides diagnostic information for hardware components.",
		L"Collects system telemetry for component health reporting.",
		L"Monitors device status and reports anomalies to the kernel.",
		L"Handles hardware resource management and configuration.",
		L"Reports peripheral device status to the system event log."
	};
	const wchar_t* description = desc_options[(rnd >> 8) % (sizeof(desc_options) / sizeof(desc_options[0]))];
	DWORD descLen = (DWORD)((wcslen(description) + 1) * sizeof(wchar_t));
	RegSetKeyValueW(dservice, NULL, L"Description", REG_SZ, description, descLen);

	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA(ENC("ntdll.dll").c_str());
	if (ntdll == NULL) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return STATUS_UNSUCCESSFUL;
	}

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS ntStatus = nt::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(ntStatus)) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return ntStatus;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	ntStatus = nt::NtLoadDriver(&serviceStr);

	if (!NT_SUCCESS(ntStatus)) {
		status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	}

	return ntStatus;
}

NTSTATUS service::StopAndRemove(const std::wstring& serviceName) {
	HMODULE ntdll = GetModuleHandleA(ENC("ntdll.dll").c_str());
	if (ntdll == NULL)
		return STATUS_UNSUCCESSFUL;

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND)
			return STATUS_SUCCESS;
		return STATUS_REGISTRY_IO_FAILED;
	}
	RegCloseKey(driver_service);

	NTSTATUS st = nt::NtUnloadDriver(&serviceStr);
	if (st != ERROR_SUCCESS) {
		status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return st;
	}

	status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS)
		return STATUS_REGISTRY_IO_FAILED;

	return st;
}
