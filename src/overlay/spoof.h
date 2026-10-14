#pragma once
#include <Windows.h>

namespace spoof {
    void RenameProcessImage(const wchar_t* fake_exe_path);
    void RenameWindowClassAndTitle(HWND hwnd, const wchar_t* title);
    void HideFromDebuggerPeb();

    constexpr const wchar_t* kNahimic   = L"NahimicSvc64.exe";
    constexpr const wchar_t* kCapframeX = L"CapFrameX.exe";
    constexpr const wchar_t* kRtss      = L"RTSS.exe";
    constexpr const wchar_t* kPlaynite  = L"Playnite.DesktopApp.exe";
    constexpr const wchar_t* kRealtek   = L"RtkAudUService64.exe";
    constexpr const wchar_t* kArmoury   = L"ArmouryCrate.Service.exe";
}
