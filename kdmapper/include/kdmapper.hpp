#pragma once

#include <Windows.h>
#include <string>

#include "overlay.hpp"

namespace kdmapper
{
	enum class AllocationMode
	{
		AllocatePool,
		AllocateIndependentPages,
		OverlayIntoHostDriver
	};

	typedef bool (*mapCallback)(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize);

	ULONG64 MapDriver(BYTE* data, ULONG64 param1 = 0, ULONG64 param2 = 0, bool free = false, bool destroyHeader = true, AllocationMode mode = AllocationMode::AllocatePool, bool PassAllocationAddressAsFirstParam = false, mapCallback callback = nullptr, NTSTATUS* exitCode = nullptr, const std::string& preferred_host = "");

	bool GetActiveOverlay(overlay::OverlayTarget& out);
	void ClearActiveOverlay();
}
