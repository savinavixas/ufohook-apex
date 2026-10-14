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

template<size_t N, uint8_t K>
struct EncStr {
	char data[N];

	constexpr EncStr(const char(&str)[N]) : data{} {
		for (size_t i = 0; i < N; i++)
			data[i] = str[i] ^ (K + (uint8_t)i);
	}

	std::string dec() const {
		std::string out(N - 1, '\0');
		for (size_t i = 0; i < N - 1; i++)
			out[i] = data[i] ^ (K + (uint8_t)i);
		return out;
	}
};

template<size_t N, uint8_t K>
struct EncWStr {
	wchar_t data[N];

	constexpr EncWStr(const wchar_t(&str)[N]) : data{} {
		for (size_t i = 0; i < N; i++)
			data[i] = str[i] ^ (K + (wchar_t)i);
	}

	std::wstring dec() const {
		std::wstring out(N - 1, L'\0');
		for (size_t i = 0; i < N - 1; i++)
			out[i] = data[i] ^ (K + (wchar_t)i);
		return out;
	}
};

#define ENC(s) []{ constexpr EncStr<sizeof(s), (uint8_t)(__LINE__ * 7 + 0x5A)> e(s); return e; }().dec()
#define ENCW(s) []{ constexpr EncWStr<sizeof(s)/sizeof(wchar_t), (uint8_t)(__LINE__ * 7 + 0x5A)> e(s); return e; }().dec()

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
