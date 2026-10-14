#include "overlay.hpp"
#include <Windows.h>
#include <algorithm>

#include "utils.hpp"
#include "intel_driver.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"

namespace overlay
{
	static const char* kAvoidPrefixes[] = {
		"ntoskrnl", "ntkrnl", "hal", "win32k", "ci.dll", "clipsp", "securekernel",
		"EasyAntiCheat", "BEDaisy", "BEClient", "vgk", "WdFilter", "WdNisDrv",
		"SgrmAgent", "mssecflt", "AppCheck", "faceit_", "Battleye",
		"ksecdd", "msrpc", "ntfs", "fastfat", "fltmgr", "cng", "tm",
		"tcpip", "ndis", "netio", "afd", "http.sys",
		"storport", "classpnp", "disk.sys", "volmgr", "mountmgr", "partmgr",
		"MpKsl", "mpsdrv", "mpssvc",
		"WDTKernel",
		"RTKVHD64", "RtkAudUService",
		"nvlddmkm", "nvidia",
		"amdkmdag", "amdkmpfd", "atikmdag",
		"HDAudBus", "portcls", "usbaudio",
		"BasicRender", "BasicDisplay",
		"intelppm",
	};

	static const char* kTier1Preferred[] = {
		"LGHUB.sys", "LGHUBUpdater.sys", "logi_joy_bus_enum.sys", "LGBusEnum.sys",
		"LogiFilter.sys", "GRazeB.sys",
		"RzDev_02a0.sys", "rzudd.sys", "rzpnk.sys", "rzpmgrk.sys", "rzvad.sys",
		"iCUE.sys", "CorsairLink3Service.sys", "CorsairLink.sys",
		"SteelSeriesService.sys", "ss_mserver.sys",
		"EVGA_PrecisionBoost.sys",
		"MSIAfterburner.sys", "RTCore64.sys",
		"GPUZ.sys", "HwRwDrv.sys",
		"HWiNFO64A.sys", "HwInfo.sys",
		"ViGEmBus.sys", "HidGuardian.sys",
		"VoiceMeeterVAIODrv.sys", "vbaudio_cable.sys",
		"ElgatoGameCapture.sys", "GCMiniHD.sys",
		"VBoxDrv.sys", "VBoxUSBMon.sys",
		"vmnetbridge.sys", "vmnetadapter.sys", "VMwareVMCI.sys",
		"OculusVrDrv.sys", "ValveVR.sys",
		"XSplit.sys",
		"MullvadWg.sys", "nordvpnlpd.sys", "ExpressVPN.sys",
		"RivaTuner64.sys", "RtkIO64.sys",
		"VirtualHere.sys",
		"procexp152.sys", "procmon24.sys",
	};

	static const char* kTier2Secondary[] = {
		"usbccgp.sys", "usbhub.sys", "USBXHCI.sys",
		"HidClass.sys", "hidusb.sys", "mouhid.sys", "kbdhid.sys",
		"BTHUSB.sys", "bthport.sys", "BthHfEnum.sys",
		"wacomrouter.sys", "WacomPen.sys", "wacommousefilter.sys",
		"srvnet.sys", "mrxsmb.sys", "mup.sys",
		"spaceport.sys", "swenum.sys", "umbus.sys",
		"nwifi.sys", "pacer.sys",
	};

	static const char* kPreferredSections[] = {
		".data",
		".rdata",
		"PAGE",
		".bss",
	};

	static bool ShouldAvoid(const std::string& name) {
		for (const char* prefix : kAvoidPrefixes) {
			size_t plen = strlen(prefix);
			if (name.size() >= plen && _strnicmp(name.c_str(), prefix, plen) == 0)
				return true;
		}
		return false;
	}

	static bool ReadDriverPEHeaders(uint64_t driver_base, std::vector<uint8_t>& out_headers) {
		out_headers.resize(0x1000);
		if (!vdrv::ReadMemory(driver_base, out_headers.data(), 0x1000))
			return false;

		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(out_headers.data());
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			return false;
		if (dos->e_lfanew <= 0 || dos->e_lfanew >= 0x800)
			return false;

		auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(out_headers.data() + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
			return false;
		if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			return false;

		return true;
	}

	static bool EvaluateDriverForOverlay(const nt::RTL_PROCESS_MODULE_INFORMATION& mod,
		uint32_t needed_bytes, OverlayTarget& out) {
		std::string short_name(reinterpret_cast<const char*>(mod.FullPathName) + mod.OffsetToFileName);
		if (short_name.empty())
			return false;
		if (ShouldAvoid(short_name))
			return false;

		uint64_t base = reinterpret_cast<uint64_t>(mod.ImageBase);
		if (!base || mod.ImageSize < 0x2000)
			return false;

		std::vector<uint8_t> headers;
		if (!ReadDriverPEHeaders(base, headers))
			return false;

		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(headers.data());
		auto nt_hdr = reinterpret_cast<PIMAGE_NT_HEADERS64>(headers.data() + dos->e_lfanew);
		PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_hdr);

		for (const char* pref_name : kPreferredSections) {
			size_t pref_len = strlen(pref_name);
			for (DWORD i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++) {
				char sec_name[9] = { 0 };
				memcpy(sec_name, sections[i].Name, 8);
				if (strncmp(sec_name, pref_name, pref_len) != 0)
					continue;

				if ((sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
					strncmp(sec_name, ".text", 5) == 0)
					continue;

				uint32_t sec_size = sections[i].Misc.VirtualSize;
				if (sections[i].SizeOfRawData > sec_size)
					sec_size = sections[i].SizeOfRawData;

				if (sec_size < needed_bytes + 0x400)
					continue;

				uint64_t sec_va = base + sections[i].VirtualAddress;

				out.driver_base = base;
				out.driver_size = mod.ImageSize;
				out.driver_name = short_name;
				out.section_vaddr = sec_va;
				out.section_size = sec_size;
				out.section_rva = sections[i].VirtualAddress;
				memcpy(out.section_name, sec_name, 8);
				out.section_name[8] = 0;
				out.original_section_characteristics = sections[i].Characteristics;
				return true;
			}
		}

		return false;
	}

	bool FindOverlayTargetNamed(const std::string& preferred_driver, uint32_t needed_bytes, OverlayTarget& out) {
		void* buffer = nullptr;
		DWORD buffer_size = 0;

		NTSTATUS status = NtQuerySystemInformation(
			static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation),
			buffer, buffer_size, &buffer_size);

		while (status == STATUS_INFO_LENGTH_MISMATCH) {
			if (buffer)
				VirtualFree(buffer, 0, MEM_RELEASE);
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!buffer)
				return false;
			status = NtQuerySystemInformation(
				static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation),
				buffer, buffer_size, &buffer_size);
		}

		if (!NT_SUCCESS(status) || !buffer) {
			if (buffer)
				VirtualFree(buffer, 0, MEM_RELEASE);
			return false;
		}

		auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
		bool found = false;

		for (ULONG i = 0; i < modules->NumberOfModules; i++) {
			const auto& mod = modules->Modules[i];
			std::string short_name(reinterpret_cast<const char*>(mod.FullPathName) + mod.OffsetToFileName);
			if (_stricmp(short_name.c_str(), preferred_driver.c_str()) != 0)
				continue;
			if (EvaluateDriverForOverlay(mod, needed_bytes, out)) {
				found = true;
				break;
			}
		}

		VirtualFree(buffer, 0, MEM_RELEASE);
		return found;
	}

	static void FisherYatesShuffle(std::vector<const char*>& v) {
		for (size_t i = v.size() - 1; i > 0; i--) {
			size_t j = kdmUtils::CryptoRand32() % (i + 1);
			std::swap(v[i], v[j]);
		}
	}

	static void ShuffleIndices(std::vector<ULONG>& v) {
		for (size_t i = v.size() - 1; i > 0; i--) {
			size_t j = kdmUtils::CryptoRand32() % (i + 1);
			std::swap(v[i], v[j]);
		}
	}

	bool FindOverlayTarget(uint32_t needed_bytes, OverlayTarget& out) {
		std::vector<const char*> tier1(kTier1Preferred, kTier1Preferred + (sizeof(kTier1Preferred) / sizeof(kTier1Preferred[0])));
		FisherYatesShuffle(tier1);
		for (const char* host : tier1) {
			if (FindOverlayTargetNamed(host, needed_bytes, out))
				return true;
		}

		void* buffer = nullptr;
		DWORD buffer_size = 0;

		NTSTATUS status = NtQuerySystemInformation(
			static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation),
			buffer, buffer_size, &buffer_size);

		while (status == STATUS_INFO_LENGTH_MISMATCH) {
			if (buffer)
				VirtualFree(buffer, 0, MEM_RELEASE);
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!buffer)
				return false;
			status = NtQuerySystemInformation(
				static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation),
				buffer, buffer_size, &buffer_size);
		}

		if (!NT_SUCCESS(status) || !buffer) {
			if (buffer)
				VirtualFree(buffer, 0, MEM_RELEASE);
			return false;
		}

		auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);

		std::vector<ULONG> candidates;
		candidates.reserve(modules->NumberOfModules);
		for (ULONG i = 0; i < modules->NumberOfModules; i++)
			candidates.push_back(i);
		ShuffleIndices(candidates);

		bool found = false;

		for (ULONG idx : candidates) {
			const auto& mod = modules->Modules[idx];
			std::string short_name(reinterpret_cast<const char*>(mod.FullPathName) + mod.OffsetToFileName);
			if (ShouldAvoid(short_name))
				continue;
			if (short_name.size() < 5)
				continue;

			auto ends_with_sys = [](const std::string& s) {
				return s.size() >= 4 && _stricmp(s.c_str() + s.size() - 4, ".sys") == 0;
			};
			if (!ends_with_sys(short_name))
				continue;

			if (EvaluateDriverForOverlay(mod, needed_bytes, out)) {
				found = true;
				break;
			}
		}

		if (!found) {
			std::vector<const char*> tier2(kTier2Secondary, kTier2Secondary + (sizeof(kTier2Secondary) / sizeof(kTier2Secondary[0])));
			FisherYatesShuffle(tier2);
			for (const char* host : tier2) {
				if (FindOverlayTargetNamed(host, needed_bytes, out)) {
					found = true;
					break;
				}
			}
		}

		VirtualFree(buffer, 0, MEM_RELEASE);
		return found;
	}

	bool IsSectionLikelyUnused(uint64_t section_vaddr, uint32_t section_size) {
		if (section_size < 0x1000)
			return false;

		uint32_t sample_size = (section_size < 0x4000) ? section_size : 0x4000;
		auto buf = std::make_unique<uint8_t[]>(sample_size);
		if (!vdrv::ReadMemory(section_vaddr, buf.get(), sample_size))
			return false;

		uint32_t zero_count = 0;
		for (uint32_t i = 0; i < sample_size; i++) {
			if (buf[i] == 0)
				zero_count++;
		}

		return (zero_count * 100 / sample_size) >= 70;
	}

	bool PrepareSection(OverlayTarget& target) {
		target.saved_bytes.resize(target.section_size);
		if (!vdrv::ReadMemory(target.section_vaddr, target.saved_bytes.data(), target.section_size))
			return false;

		ULONG new_prot = PAGE_EXECUTE_READWRITE;
		BOOLEAN result = vdrv::MmSetPageProtection(target.section_vaddr, target.section_size, new_prot);
		if (!result)
			return false;

		return true;
	}

	bool RestoreSection(const OverlayTarget& target) {
		if (target.saved_bytes.empty())
			return false;

		if (!vdrv::WriteMemory(target.section_vaddr, (void*)target.saved_bytes.data(), target.saved_bytes.size()))
			return false;

		ULONG restored_prot = PAGE_READWRITE;
		if (target.original_section_characteristics & IMAGE_SCN_MEM_EXECUTE) {
			restored_prot = (target.original_section_characteristics & IMAGE_SCN_MEM_WRITE) ?
				PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
		}
		else if (!(target.original_section_characteristics & IMAGE_SCN_MEM_WRITE)) {
			restored_prot = PAGE_READONLY;
		}

		vdrv::MmSetPageProtection(target.section_vaddr, (uint32_t)target.saved_bytes.size(), restored_prot);
		return true;
	}
}
