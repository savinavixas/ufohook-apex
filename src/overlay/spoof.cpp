#include "spoof.h"
#include <winternl.h>
#include <cwchar>

typedef struct _PEB_LDR_DATA_FULL {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_FULL;

typedef struct _LDR_DATA_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_ENTRY;

namespace spoof {

static void SetUnicodeString(UNICODE_STRING* us, const wchar_t* value) {
    size_t len = wcslen(value);
    size_t bytes = len * sizeof(wchar_t);
    static wchar_t storage[2][MAX_PATH] = {};
    static int slot = 0;
    slot = (slot + 1) & 1;
    wcscpy_s(storage[slot], MAX_PATH, value);
    us->Buffer = storage[slot];
    us->Length = (USHORT)bytes;
    us->MaximumLength = (USHORT)(bytes + sizeof(wchar_t));
}

void RenameProcessImage(const wchar_t* fakePath) {
    if (!fakePath) return;
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (!peb || !peb->ProcessParameters) return;

    RTL_USER_PROCESS_PARAMETERS* p = peb->ProcessParameters;
    SetUnicodeString(&p->ImagePathName, fakePath);
    SetUnicodeString(&p->CommandLine,   fakePath);

    PEB_LDR_DATA_FULL* ldr = (PEB_LDR_DATA_FULL*)peb->Ldr;
    if (!ldr) return;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LDR_DATA_ENTRY* first = CONTAINING_RECORD(head->Flink, LDR_DATA_ENTRY, InLoadOrderLinks);

    const wchar_t* leaf = fakePath;
    for (const wchar_t* w = fakePath; *w; ++w)
        if (*w == L'\\' || *w == L'/') leaf = w + 1;

    SetUnicodeString(&first->FullDllName, fakePath);
    SetUnicodeString(&first->BaseDllName, leaf);
}

void RenameWindowClassAndTitle(HWND hwnd, const wchar_t* title) {
    if (!hwnd || !title) return;
    SetWindowTextW(hwnd, title);
}

void HideFromDebuggerPeb() {
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (!peb) return;
    peb->BeingDebugged = FALSE;
    *((DWORD*)((BYTE*)peb + 0xBC)) &= ~0x70;
}

}
