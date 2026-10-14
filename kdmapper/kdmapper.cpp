#include "kdmapper.hpp"
#include <Windows.h>

#include "utils.hpp"
#include "intel_driver.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"

void RelocateImageByDelta(portable_executable::vec_relocs relocs, const ULONG64 delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<ULONG64*>(current_reloc.address + offset) += delta;
		}
	}
}

bool FixSecurityCookie(void* local_image, ULONG64 kernel_image_base)
{
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
		return true;

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
		return true;

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image;

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232)
		return false;

	uintptr_t new_cookie = ((uintptr_t)kdmUtils::CryptoRand32() << 32) | kdmUtils::CryptoRand32();
	if (new_cookie == 0x2B992DDFA232)
		new_cookie++;

	*(uintptr_t*)(stack_cookie) = new_cookie;
	return true;
}

bool ResolveImports(portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = kdmUtils::GetKernelModuleAddress(current_import.module_name);
		if (!Module)
			return false;

		for (auto& current_function_data : current_import.function_datas) {
			ULONG64 function_address = intel_driver::GetKernelModuleExport(Module, current_function_data.name);

			if (!function_address) {
				if (Module != intel_driver::ntoskrnlAddr) {
					function_address = intel_driver::GetKernelModuleExport(intel_driver::ntoskrnlAddr, current_function_data.name);
					if (!function_address)
						return false;
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}

void WipeImportTable(void* local_image) {
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return;

	DWORD import_va = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD import_size = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (import_va && import_size) {
		memset(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image) + import_va), 0, import_size);
	}

	headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	DWORD iat_va = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	DWORD iat_size = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
	if (iat_va && iat_size) {
		headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
		headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	}
}

void WipeRelocData(void* local_image) {
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return;

	DWORD reloc_va = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD reloc_size = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (reloc_va && reloc_size) {
		memset(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image) + reloc_va), 0, reloc_size);
	}

	headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
	headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
}

void WipeSectionNames(void* local_image) {
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return;

	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		memset(sections[i].Name, 0, IMAGE_SIZEOF_SHORT_NAME);
	}
}

void WipeDebugDirectory(void* local_image) {
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return;

	DWORD debug_va = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
	DWORD debug_size = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	if (debug_va && debug_size) {
		auto debug_dir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(reinterpret_cast<ULONG64>(local_image) + debug_va);
		DWORD num_entries = debug_size / sizeof(IMAGE_DEBUG_DIRECTORY);
		for (DWORD i = 0; i < num_entries; ++i) {
			if (debug_dir[i].PointerToRawData && debug_dir[i].SizeOfData) {
				memset(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image) + debug_dir[i].AddressOfRawData), 0, debug_dir[i].SizeOfData);
			}
		}
		memset(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image) + debug_va), 0, debug_size);
	}

	headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
	headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
}

void WipeResourceDirectory(void* local_image) {
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return;

	DWORD rsrc_va = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	DWORD rsrc_size = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
	if (rsrc_va && rsrc_size) {
		memset(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image) + rsrc_va), 0, rsrc_size);
	}

	headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0;
	headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0;
}

void WipeExportDirectory(void* local_image) {
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return;

	DWORD export_va = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD export_size = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (export_va && export_size) {
		auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<ULONG64>(local_image) + export_va);

		if (export_dir->Name) {
			char* name_ptr = reinterpret_cast<char*>(reinterpret_cast<ULONG64>(local_image) + export_dir->Name);
			memset(name_ptr, 0, strlen(name_ptr));
		}

		if (export_dir->AddressOfNames && export_dir->NumberOfNames) {
			auto names = reinterpret_cast<DWORD*>(reinterpret_cast<ULONG64>(local_image) + export_dir->AddressOfNames);
			for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
				if (names[i]) {
					char* fn_name = reinterpret_cast<char*>(reinterpret_cast<ULONG64>(local_image) + names[i]);
					memset(fn_name, 0, strlen(fn_name));
				}
			}
		}

		memset(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image) + export_va), 0, export_size);
	}

	headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
	headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
}

void WipeRemainingDirectories(void* local_image) {
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return;

	const DWORD skip[] = {
		IMAGE_DIRECTORY_ENTRY_IMPORT,
		IMAGE_DIRECTORY_ENTRY_BASERELOC,
		IMAGE_DIRECTORY_ENTRY_DEBUG,
		IMAGE_DIRECTORY_ENTRY_RESOURCE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		IMAGE_DIRECTORY_ENTRY_IAT,
		IMAGE_DIRECTORY_ENTRY_EXCEPTION,
	};

	for (DWORD dir = 0; dir < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; dir++) {
		bool already_handled = false;
		for (auto s : skip) {
			if (dir == s) { already_handled = true; break; }
		}
		if (already_handled)
			continue;

		auto& entry = headers->OptionalHeader.DataDirectory[dir];
		if (entry.VirtualAddress && entry.Size) {
			if (dir != IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG && dir != IMAGE_DIRECTORY_ENTRY_TLS) {
				memset(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image) + entry.VirtualAddress), 0, entry.Size);
			}
			entry.VirtualAddress = 0;
			entry.Size = 0;
		}
	}
}

void DestroyHeaderEnhanced(void* local_image, DWORD headerSize) {
	HCRYPTPROV hProv = 0;
	if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		CryptGenRandom(hProv, headerSize, reinterpret_cast<BYTE*>(local_image));
		CryptReleaseContext(hProv, 0);
	}
	else {
		memset(local_image, 0, headerSize);
	}
}

ULONG64 kdmapper::MapDriver(BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode) {

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);

	if (!nt_headers)
		return 0;

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 0;

	ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	ULONG64 kernel_image_base = 0;
	if (mode == AllocationMode::AllocateIndependentPages)
	{
		kernel_image_base = intel_driver::MmAllocateIndependentPagesEx(image_size);
	}
	else {
		kernel_image_base = intel_driver::AllocatePool(nt::POOL_TYPE::NonPagedPool, image_size);
	}

	if (!kernel_image_base) {
		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do {
		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<ULONG64>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		ULONG64 realBase = kernel_image_base;
		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
		}

		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!FixSecurityCookie(local_image_base, kernel_image_base))
			return 0;

		if (!ResolveImports(portable_executable::GetImports(local_image_base))) {
			kernel_image_base = realBase;
			break;
		}

		WipeImportTable(local_image_base);
		WipeRelocData(local_image_base);
		WipeDebugDirectory(local_image_base);
		WipeResourceDirectory(local_image_base);
		WipeExportDirectory(local_image_base);
		WipeRemainingDirectories(local_image_base);
		WipeSectionNames(local_image_base);

		if (destroyHeader) {
			DestroyHeaderEnhanced(local_image_base, TotalVirtualHeaderSize);
		}

		if (!intel_driver::WriteMemory(realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
			kernel_image_base = realBase;
			break;
		}

		if (mode == AllocationMode::AllocateIndependentPages)
		{
			for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
				auto sec = &IMAGE_FIRST_SECTION(nt_headers)[i];
				uintptr_t secAddr = kernel_image_base + sec->VirtualAddress;
				uint32_t secSize = sec->Misc.VirtualSize;

				if (secSize <= 0)
					continue;

				ULONG prot = PAGE_READONLY;

				if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
					prot = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ?
						PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
					prot = PAGE_READWRITE;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_READ) {
					prot = PAGE_READONLY;
				}

				intel_driver::MmSetPageProtection(secAddr, secSize, prot);
			}
		}

		const ULONG64 address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		if (callback) {
			if (!callback(&param1, &param2, realBase, image_size)) {
				kernel_image_base = realBase;
				break;
			}
		}

		NTSTATUS status = 0;
		if (!intel_driver::CallKernelFunction(&status, address_of_entry_point, (PassAllocationAddressAsFirstParam ? realBase : param1), param2)) {
			kernel_image_base = realBase;
			break;
		}

		if (exitCode)
			*exitCode = status;

		if (free) {
			bool free_status = false;

			if (mode == AllocationMode::AllocateIndependentPages)
				free_status = intel_driver::MmFreeIndependentPages(realBase, image_size);
			else
				free_status = intel_driver::FreePool(realBase);
		}

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);


	VirtualFree(local_image_base, 0, MEM_RELEASE);

	bool free_status = false;

	if (mode == AllocationMode::AllocateIndependentPages)
		free_status = intel_driver::MmFreeIndependentPages(kernel_image_base, image_size);
	else
		free_status = intel_driver::FreePool(kernel_image_base);

	return 0;
}
