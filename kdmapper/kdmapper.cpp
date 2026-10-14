#include "kdmapper.hpp"
#include <Windows.h>
#include <vector>

#include "utils.hpp"
#include "intel_driver.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"

struct ImportSite {
	uint32_t offset;
	uint64_t target_fn;
	uint8_t  kind;
};

static size_t CountImportSites(void* raw_image) {
	auto headers = portable_executable::GetNtHeaders(raw_image);
	if (!headers)
		return 0;

	size_t count = 0;
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD s = 0; s < headers->FileHeader.NumberOfSections; s++) {
		if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
			continue;
		uint32_t raw_off = sections[s].PointerToRawData;
		uint32_t raw_sz  = sections[s].SizeOfRawData;
		if (!raw_off || !raw_sz)
			continue;
		const uint8_t* base = reinterpret_cast<const uint8_t*>(raw_image) + raw_off;
		for (uint32_t i = 0; i + 6 <= raw_sz; i++) {
			if (base[i] == 0xFF && (base[i + 1] == 0x25 || base[i + 1] == 0x15))
				count++;
		}
	}
	return count;
}

static size_t ScanImportSitesLocal(uint8_t* local_image_base, std::vector<ImportSite>& out, uint32_t iat_va, uint32_t iat_size) {
	auto headers = portable_executable::GetNtHeaders(local_image_base);
	if (!headers)
		return 0;

	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD s = 0; s < headers->FileHeader.NumberOfSections; s++) {
		if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
			continue;
		uint32_t start = sections[s].VirtualAddress;
		uint32_t vend  = start + sections[s].Misc.VirtualSize;
		for (uint32_t i = start; i + 6 <= vend; i++) {
			uint8_t b1 = local_image_base[i];
			uint8_t b2 = local_image_base[i + 1];
			if (b1 != 0xFF)
				continue;
			if (b2 != 0x25 && b2 != 0x15)
				continue;
			int32_t disp = *reinterpret_cast<int32_t*>(local_image_base + i + 2);
			int64_t target_rva64 = (int64_t)i + 6 + (int64_t)disp;
			if (target_rva64 < 0 || target_rva64 >= 0x7FFFFFFF)
				continue;
			uint32_t target_rva = (uint32_t)target_rva64;
			if (iat_va && iat_size) {
				if (target_rva < iat_va || target_rva + 8 > iat_va + iat_size)
					continue;
			}
			uint64_t iat_value = *reinterpret_cast<uint64_t*>(local_image_base + target_rva);
			if (!iat_value)
				continue;
			out.push_back({ i, iat_value, b2 });
		}
	}
	return out.size();
}

static void BuildDiversifiedStub(uint8_t* out, uint64_t target, uint32_t shape_rand) {
	for (int i = 0; i < 16; i++)
		out[i] = 0x90;

	uint32_t shape = shape_rand % 4;
	switch (shape) {
	case 0: {
		out[0]  = 0x48;
		out[1]  = 0xB8;
		*reinterpret_cast<uint64_t*>(out + 2) = target;
		out[10] = 0xFF;
		out[11] = 0xE0;
		break;
	}
	case 1: {
		out[0]  = 0x49;
		out[1]  = 0xBA;
		*reinterpret_cast<uint64_t*>(out + 2) = target;
		out[10] = 0x41;
		out[11] = 0xFF;
		out[12] = 0xE2;
		break;
	}
	case 2: {
		out[0]  = 0x49;
		out[1]  = 0xBB;
		*reinterpret_cast<uint64_t*>(out + 2) = target;
		out[10] = 0x41;
		out[11] = 0xFF;
		out[12] = 0xE3;
		break;
	}
	case 3: {
		uint32_t lo = static_cast<uint32_t>(target & 0xFFFFFFFF);
		uint32_t hi = static_cast<uint32_t>(target >> 32);
		out[0] = 0x68;
		*reinterpret_cast<uint32_t*>(out + 1) = lo;
		out[5] = 0xC7;
		out[6] = 0x44;
		out[7] = 0x24;
		out[8] = 0x04;
		*reinterpret_cast<uint32_t*>(out + 9) = hi;
		out[13] = 0xC3;
		break;
	}
	}
}

static bool NeutralizeImportWrappers(uint8_t* local_image_base, uint64_t kernel_image_base_virtual,
	uint32_t image_size, uint32_t trampoline_space, uint32_t& out_used) {
	out_used = 0;

	auto headers = portable_executable::GetNtHeaders(local_image_base);
	if (!headers)
		return false;

	uint32_t iat_va   = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	uint32_t iat_size = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

	std::vector<ImportSite> sites;
	ScanImportSitesLocal(local_image_base, sites, iat_va, iat_size);
	if (sites.empty())
		return true;

	const uint32_t stub_size = 16;
	uint32_t needed = (uint32_t)sites.size() * stub_size;
	if (needed > trampoline_space)
		return false;

	uint8_t* tramp_base_local = local_image_base + image_size;
	uint64_t tramp_base_kernel = kernel_image_base_virtual + image_size;

	for (size_t i = 0; i < sites.size(); i++) {
		const auto& site = sites[i];
		uint8_t* tramp = tramp_base_local + i * stub_size;
		uint64_t tramp_kaddr = tramp_base_kernel + i * stub_size;

		BuildDiversifiedStub(tramp, site.target_fn, kdmUtils::CryptoRand32());

		uint8_t* site_ptr = local_image_base + site.offset;
		uint64_t site_kaddr = kernel_image_base_virtual + site.offset;
		int64_t rel = (int64_t)tramp_kaddr - (int64_t)(site_kaddr + 5);
		if (rel > 0x7FFFFFFFLL || rel < -0x80000000LL)
			return false;

		site_ptr[0] = (site.kind == 0x25) ? 0xE9 : 0xE8;
		*reinterpret_cast<int32_t*>(site_ptr + 1) = (int32_t)rel;
		site_ptr[5] = 0x90;
	}

	out_used = needed;
	return true;
}

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

	size_t ff25_count = CountImportSites(data);
	uint32_t trampoline_space = (uint32_t)((ff25_count + 32) * 16);
	trampoline_space = (trampoline_space + 0xFFF) & ~0xFFF;

	uint32_t alloc_virt_total = image_size + trampoline_space;

	void* local_image_base = VirtualAlloc(nullptr, alloc_virt_total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);
	uint32_t kernel_alloc_size = image_size + trampoline_space;

	ULONG64 kernel_image_base = 0;
	if (mode == AllocationMode::AllocateIndependentPages)
	{
		kernel_image_base = intel_driver::MmAllocateIndependentPagesEx(kernel_alloc_size);
	}
	else {
		kernel_image_base = intel_driver::AllocatePool(nt::POOL_TYPE::NonPagedPool, kernel_alloc_size);
	}

	if (!kernel_image_base) {
		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	intel_driver::ScopedPriorityBoost _mapBoost;

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

		uint32_t tramp_used = 0;
		if (!NeutralizeImportWrappers(
			reinterpret_cast<uint8_t*>(local_image_base),
			kernel_image_base,
			nt_headers->OptionalHeader.SizeOfImage,
			trampoline_space,
			tramp_used)) {
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

		uint32_t write_size = image_size + ((tramp_used + 0xF) & ~0xF);
		if (!intel_driver::WriteMemory(realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), write_size)) {
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

			if (tramp_used) {
				uintptr_t tramp_kaddr = kernel_image_base + nt_headers->OptionalHeader.SizeOfImage;
				uint32_t tramp_region_size = (tramp_used + 0xFFF) & ~0xFFF;
				intel_driver::MmSetPageProtection(tramp_kaddr, tramp_region_size, PAGE_EXECUTE_READ);
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
				free_status = intel_driver::MmFreeIndependentPages(realBase, kernel_alloc_size);
			else
				free_status = intel_driver::FreePool(realBase);
		}

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);


	VirtualFree(local_image_base, 0, MEM_RELEASE);

	bool free_status = false;

	if (mode == AllocationMode::AllocateIndependentPages)
		free_status = intel_driver::MmFreeIndependentPages(kernel_image_base, kernel_alloc_size);
	else
		free_status = intel_driver::FreePool(kernel_image_base);

	return 0;
}
