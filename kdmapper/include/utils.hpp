#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <random>

#if defined(DISABLE_OUTPUT)
#define kdmLog(content)
#else
#define kdmLog(content) std::wcout << content
#endif

namespace kdmUtils
{
	std::wstring GetFullTempPath();
	bool ReadFileToMemory(const std::wstring& file_path, std::vector<BYTE>* out_buffer);
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);
	uint64_t GetKernelModuleAddress(const std::string& module_name);
	BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
	uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	PVOID FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size);
	std::wstring GetCurrentAppFolder();

	inline uint32_t CryptoRand32() {
		uint32_t val;
		HCRYPTPROV hProv = 0;
		CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
		CryptGenRandom(hProv, sizeof(val), reinterpret_cast<BYTE*>(&val));
		CryptReleaseContext(hProv, 0);
		return val;
	}

	inline std::wstring GenerateCryptoRandomName(int minLen = 8, int maxLen = 14) {
		static const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyz";
		int len = minLen + (CryptoRand32() % (maxLen - minLen + 1));
		std::wstring name;
		name.resize(len);
		for (int i = 0; i < len; i++) {
			name[i] = charset[CryptoRand32() % (sizeof(charset) / sizeof(wchar_t) - 1)];
		}
		return name;
	}

	inline ULONG GenerateRandomPoolTag() {
		union {
			ULONG tag;
			char bytes[4];
		} t;
		static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		for (int i = 0; i < 4; i++) {
			t.bytes[i] = charset[CryptoRand32() % (sizeof(charset) - 1)];
		}
		return t.tag;
	}
}
