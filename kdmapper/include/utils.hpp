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

#define ENC(s) []{ constexpr EncStr<sizeof(s), (uint8_t)(__LINE__ * 11 + 0xA7 + __COUNTER__)> e(s); return e; }().dec()
#define ENCW(s) []{ constexpr EncWStr<sizeof(s)/sizeof(wchar_t), (uint8_t)(__LINE__ * 11 + 0xA7 + __COUNTER__)> e(s); return e; }().dec()

namespace kdmUtils
{
	std::wstring GetFullTempPath();
	std::wstring GetSystemDataPath();
	bool ReadFileToMemory(const std::wstring& file_path, std::vector<BYTE>* out_buffer);
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);
	uint64_t GetKernelModuleAddress(const std::string& module_name);
	BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
	uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	PVOID FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size);
	std::wstring GetCurrentAppFolder();
	bool IsHvciWithBlocklistActive();

	inline uint32_t CryptoRand32() {
		uint32_t val;
		HCRYPTPROV hProv = 0;
		CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
		CryptGenRandom(hProv, sizeof(val), reinterpret_cast<BYTE*>(&val));
		CryptReleaseContext(hProv, 0);
		return val;
	}

	inline void CryptoFill(void* buf, size_t sz) {
		HCRYPTPROV hProv = 0;
		if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
			CryptGenRandom(hProv, (DWORD)sz, reinterpret_cast<BYTE*>(buf));
			CryptReleaseContext(hProv, 0);
		}
	}

	inline std::wstring GenerateCryptoRandomName(int minLen = 8, int maxLen = 14) {
		static const wchar_t charset_lead[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		static const wchar_t charset_body[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		int len = minLen + (CryptoRand32() % (maxLen - minLen + 1));
		std::wstring name;
		name.resize(len);
		name[0] = charset_lead[CryptoRand32() % (sizeof(charset_lead) / sizeof(wchar_t) - 1)];
		for (int i = 1; i < len; i++) {
			name[i] = charset_body[CryptoRand32() % (sizeof(charset_body) / sizeof(wchar_t) - 1)];
		}
		return name;
	}

	inline std::wstring GenerateServiceLikeName() {
		static const wchar_t* leaf[] = { L"Svc", L"Mgr", L"Agent", L"Host", L"Client", L"Core", L"Daemon", L"Monitor", L"Helper", L"Worker", L"Engine", L"Bridge" };
		static const wchar_t* prefix[] = { L"Win", L"Ms", L"Sys", L"Net", L"Dev", L"Hid", L"Pci", L"Usb", L"Hw", L"Dr", L"Fs", L"Io" };
		static const wchar_t charset_mid[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
		int mid_len = 2 + (CryptoRand32() % 4);
		std::wstring mid;
		mid.resize(mid_len);
		for (int i = 0; i < mid_len; i++)
			mid[i] = charset_mid[CryptoRand32() % (sizeof(charset_mid) / sizeof(wchar_t) - 1)];
		std::wstring name = prefix[CryptoRand32() % (sizeof(prefix) / sizeof(prefix[0]))];
		name += mid;
		name += leaf[CryptoRand32() % (sizeof(leaf) / sizeof(leaf[0]))];
		return name;
	}

	inline ULONG GenerateRandomPoolTag() {
		static const char legit_tags[][5] = {
			{ 'M','m','P','g','D' }, { 'F','i','l','e','\0' }, { 'N','t','F','s','\0' },
			{ 'U','s','b','P','\0' }, { 'T','d','x','\0','\0' }, { 'A','c','p','i','\0' },
			{ 'N','d','i','s','\0' }, { 'K','T','S','0','\0' }, { 'V','a','d','S','\0' },
			{ 'E','T','W','I','\0' }, { 'P','n','P','I','\0' }, { 'S','e','c','a','\0' },
			{ 'M','S','D','T','\0' }, { 'D','p','W','I','\0' }, { 'K','r','n','l','\0' },
			{ 'K','m','r','l','\0' }, { 'U','s','b','D','\0' }, { 'W','m','I','P','\0' }
		};
		union {
			ULONG tag;
			char bytes[4];
		} t;
		const char* pick = legit_tags[CryptoRand32() % (sizeof(legit_tags) / sizeof(legit_tags[0]))];
		for (int i = 0; i < 4; i++)
			t.bytes[i] = pick[i] ? pick[i] : ('A' + (char)(CryptoRand32() % 26));
		return t.tag;
	}
}
