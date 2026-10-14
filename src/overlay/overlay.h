#pragma once
#include <Windows.h>
#include <d3d11_1.h>
#include <dxgi1_3.h>
#include <d2d1_3.h>
#include <dwrite.h>
#include <dcomp.h>
#include <wrl/client.h>
#include <string>

using Microsoft::WRL::ComPtr;

struct Color {
    float r, g, b, a;
    constexpr Color(float R=1, float G=1, float B=1, float A=1) : r(R), g(G), b(B), a(A) {}
    D2D1_COLOR_F d2d() const { return D2D1::ColorF(r, g, b, a); }
    static Color RGBA(int R, int G, int B, int A=255) {
        return { R/255.f, G/255.f, B/255.f, A/255.f };
    }
};

class Overlay {
public:
    bool Create(const wchar_t* gameWindowTitle);
    void Destroy();

    bool Pump();
    void BeginFrame();
    void EndFrame();

    void DrawLine(float x1, float y1, float x2, float y2, Color c, float thickness = 1.0f);
    void DrawRect(float x, float y, float w, float h, Color c, float thickness = 1.0f);
    void DrawFilledRect(float x, float y, float w, float h, Color c);
    void DrawCorneredBox(float x, float y, float w, float h, Color c, float thickness = 1.5f);
    void DrawCircle(float x, float y, float r, Color c, float thickness = 1.0f);
    void DrawFilledCircle(float x, float y, float r, Color c);
    void DrawText(float x, float y, const wchar_t* text, Color c, float size = 12.0f,
                  bool centered = false, bool outline = true);
    void DrawHealthBar(float x, float y, float w, float h, float ratio, bool vertical = true);
    void DrawShieldBar(float x, float y, float w, float h, float ratio, bool vertical = true);

    int Width()  const { return width_;  }
    int Height() const { return height_; }
    HWND Hwnd()  const { return hwnd_;   }
    bool HasGame() const { return game_ && IsWindow(game_); }

private:
    bool CreateWin(const wchar_t* targetTitle);
    bool CreateDeviceStack();
    bool CreateSwapAndTarget();
    void FollowGame();
    void Resize(int w, int h);

    HWND hwnd_   = nullptr;
    HWND game_   = nullptr;
    int  width_  = 0;
    int  height_ = 0;
    std::wstring game_title_;

    ComPtr<ID3D11Device1>        d3d_;
    ComPtr<ID3D11DeviceContext1> ctx_;
    ComPtr<IDXGIDevice1>         dxgi_;
    ComPtr<IDXGIFactory2>        fac_;
    ComPtr<IDXGISwapChain1>      swap_;

    ComPtr<IDCompositionDevice>  dcomp_;
    ComPtr<IDCompositionTarget>  dcomp_tgt_;
    ComPtr<IDCompositionVisual>  dcomp_vis_;

    ComPtr<ID2D1Factory1>        d2d_fac_;
    ComPtr<ID2D1Device>          d2d_dev_;
    ComPtr<ID2D1DeviceContext>   d2d_;
    ComPtr<ID2D1Bitmap1>         d2d_tgt_;
    ComPtr<ID2D1SolidColorBrush> brush_;

    ComPtr<IDWriteFactory>       dw_fac_;
    ComPtr<IDWriteTextFormat>    dw_fmt_;
};
