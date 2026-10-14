#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace overlay
{
	struct OverlayTarget {
		uint64_t driver_base;
		uint32_t driver_size;
		std::string driver_name;

		uint64_t section_vaddr;
		uint32_t section_size;
		uint32_t section_rva;
		char     section_name[9];

		uint32_t original_section_characteristics;
		std::vector<uint8_t> saved_bytes;
	};

	bool FindOverlayTarget(uint32_t needed_bytes, OverlayTarget& out);
	bool FindOverlayTargetNamed(const std::string& preferred_driver, uint32_t needed_bytes, OverlayTarget& out);

	bool PrepareSection(OverlayTarget& target);
	bool RestoreSection(const OverlayTarget& target);

	bool IsSectionLikelyUnused(uint64_t section_vaddr, uint32_t section_size);
}
