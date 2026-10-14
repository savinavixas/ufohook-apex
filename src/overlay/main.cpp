#include "overlay.h"
#include "menu.h"
#include "esp.h"
#include "spoof.h"
#include <chrono>
#include <thread>
#include <vector>

static ESPConfig g_esp;
static bool  g_crosshair = true;
static int   g_crosshair_style = 0;
static bool  g_watermark = true;
static int   g_fps_limit = 144;

static std::vector<Entity> FakeEntities() {
    std::vector<Entity> v;
    Entity a{};
    a.feet = { 10, 0,  28 }; a.head = { 10, 1.8f, 28 };
    a.health = 72.f; a.shield = 50.f; a.max_shield = 100.f;
    a.distance = 48.f; a.visible = true;
    a.name = L"Pathfinder [LVL 112]"; a.weapon = L"R-301";
    v.push_back(a);
    Entity b{};
    b.feet = { -14, 0, 44 }; b.head = { -14, 1.8f, 44 };
    b.health = 100.f; b.shield = 100.f; b.max_shield = 125.f;
    b.distance = 120.f; b.visible = false; b.team = 1;
    b.name = L"Wraith"; b.weapon = L"Peacekeeper";
    v.push_back(b);
    return v;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    spoof::HideFromDebuggerPeb();
    spoof::RenameProcessImage(L"C:\\Program Files\\Nahimic\\NahimicService\\NahimicSvc64.exe");

    Overlay ov;
    if (!ov.Create(L"Apex Legends")) {
        if (!ov.Create(nullptr)) return 1;
    }
    spoof::RenameWindowClassAndTitle(ov.Hwnd(), L"Nahimic Mirroring Device");

    Menu menu;
    menu.BindToggleKey(VK_INSERT);
    menu.SetTitle(L"UFOHook  ::  Apex");
    menu.SetAccent(Color(1.0f, 0.25f, 0.35f, 1.0f));

    menu.AddHeader(L"ESP");
    menu.AddToggle(L"Enabled",         &g_esp.enabled);
    menu.AddToggle(L"Boxes",           &g_esp.box);
    menu.AddCombo (L"Box style",       &g_esp.box_style, { L"Full", L"Cornered", L"Filled" });
    menu.AddToggle(L"Snap lines",      &g_esp.snap_lines);
    menu.AddToggle(L"Skeleton",        &g_esp.skeleton);
    menu.AddToggle(L"Health bar",      &g_esp.health_bar);
    menu.AddToggle(L"Shield bar",      &g_esp.shield_bar);
    menu.AddToggle(L"Name",            &g_esp.name);
    menu.AddToggle(L"Distance",        &g_esp.distance);
    menu.AddToggle(L"Weapon",          &g_esp.weapon);
    menu.AddToggle(L"Team check",      &g_esp.team_check);
    menu.AddToggle(L"Visibility only", &g_esp.visibility_check);
    menu.AddSlider(L"Max distance",    &g_esp.max_distance, 10.0f, 500.0f);

    menu.AddHeader(L"Colors");
    menu.AddColor(L"Visible",   &g_esp.col_visible);
    menu.AddColor(L"Occluded",  &g_esp.col_occluded);
    menu.AddColor(L"Skeleton",  &g_esp.col_skeleton);
    menu.AddColor(L"Snap line", &g_esp.col_snap);

    menu.AddHeader(L"Misc");
    menu.AddToggle(L"Crosshair",      &g_crosshair);
    menu.AddCombo (L"Crosshair style",&g_crosshair_style, { L"Dot", L"Plus", L"T" });
    menu.AddToggle(L"Watermark",      &g_watermark);
    menu.AddIntSlider(L"FPS limit",   &g_fps_limit, 30, 500);
    menu.AddButton(L"Unload", []() { PostQuitMessage(0); });

    ViewMatrix identity{};
    for (int i = 0; i < 4; ++i) identity.m[i][i] = 1.0f;

    auto frame_target = std::chrono::nanoseconds(1'000'000'000 / 144);
    while (ov.Pump()) {
        auto start = std::chrono::steady_clock::now();
        menu.Tick();

        ov.BeginFrame();

        auto ents = FakeEntities();
        for (auto& e : ents) DrawEntity(ov, e, g_esp, identity, 0);

        if (g_crosshair) {
            float cx = ov.Width()  * 0.5f;
            float cy = ov.Height() * 0.5f;
            Color xc(0, 1.f, 0.6f, 1);
            if (g_crosshair_style == 0) ov.DrawFilledCircle(cx, cy, 1.5f, xc);
            else if (g_crosshair_style == 1) {
                ov.DrawLine(cx - 6, cy, cx + 6, cy, xc, 1.0f);
                ov.DrawLine(cx, cy - 6, cx, cy + 6, xc, 1.0f);
            } else {
                ov.DrawLine(cx - 6, cy, cx + 6, cy, xc, 1.0f);
                ov.DrawLine(cx, cy, cx, cy + 6, xc, 1.0f);
            }
        }

        if (g_watermark) {
            ov.DrawFilledRect(10, 10, 160, 20, Color(0, 0, 0, 0.55f));
            ov.DrawText(16, 14, L"UFOHook   ESP  :: v0.1", Color(1, 0.4f, 0.5f, 1), 11.f, false, false);
        }

        menu.Draw(ov);

        ov.EndFrame();

        if (g_fps_limit > 0) {
            frame_target = std::chrono::nanoseconds(1'000'000'000ll / g_fps_limit);
            auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed < frame_target)
                std::this_thread::sleep_for(frame_target - elapsed);
        }
    }

    ov.Destroy();
    return 0;
}
