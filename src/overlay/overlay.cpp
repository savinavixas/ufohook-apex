#include "overlay.h"
#include <dwmapi.h>
#include <cmath>
#include <algorithm>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "dcomp.lib")
#pragma comment(lib, "dwmapi.lib")

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}

bool Overlay::Create(const wchar_t* gameWindowTitle) {
    game_title_ = gameWindowTitle ? gameWindowTitle : L"";
    if (!CreateWin(gameWindowTitle))      return false;
    if (!CreateDeviceStack())             return false;
    if (!CreateSwapAndTarget())           return false;
    FollowGame();
    return true;
}

bool Overlay::CreateWin(const wchar_t* targetTitle) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"Shell_InputSwitchTopLevelWindow";
    RegisterClassExW(&wc);

    RECT r{ 0, 0, 1920, 1080 };
    if (targetTitle && *targetTitle) {
        HWND g = FindWindowW(nullptr, targetTitle);
        if (g) {
            RECT gr; GetClientRect(g, &gr);
            r = gr;
            game_ = g;
        }
    }
    if (r.right - r.left < 32 || r.bottom - r.top < 32) {
        r = { 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN) };
    }
    width_  = r.right  - r.left;
    height_ = r.bottom - r.top;

    DWORD ex = WS_EX_NOACTIVATE
             | WS_EX_TOPMOST
             | WS_EX_TRANSPARENT
             | WS_EX_TOOLWINDOW
             | WS_EX_NOREDIRECTIONBITMAP;

    hwnd_ = CreateWindowExW(ex, wc.lpszClassName, L"",
                            WS_POPUP,
                            0, 0, width_, height_,
                            nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd_) return false;

    SetWindowDisplayAffinity(hwnd_, WDA_EXCLUDEFROMCAPTURE);
    ShowWindow(hwnd_, SW_SHOWNOACTIVATE);
    return true;
}

bool Overlay::CreateDeviceStack() {
    UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_SINGLETHREADED;
    D3D_FEATURE_LEVEL want[] = { D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0 };
    ComPtr<ID3D11Device>        base;
    ComPtr<ID3D11DeviceContext> baseCtx;
    HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
                                   want, 2, D3D11_SDK_VERSION, &base, nullptr, &baseCtx);
    if (FAILED(hr)) return false;
    if (FAILED(base.As(&d3d_)) || FAILED(baseCtx.As(&ctx_))) return false;
    if (FAILED(d3d_.As(&dxgi_))) return false;
    dxgi_->SetMaximumFrameLatency(1);

    ComPtr<IDXGIAdapter> ad;
    dxgi_->GetAdapter(&ad);
    if (FAILED(ad->GetParent(IID_PPV_ARGS(&fac_)))) return false;

    D2D1_FACTORY_OPTIONS opts{};
    if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, opts, d2d_fac_.GetAddressOf()))) return false;
    if (FAILED(d2d_fac_->CreateDevice(dxgi_.Get(), &d2d_dev_))) return false;
    if (FAILED(d2d_dev_->CreateDeviceContext(D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &d2d_))) return false;
    d2d_->SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
    d2d_->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE);

    if (FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                                   reinterpret_cast<IUnknown**>(dw_fac_.GetAddressOf())))) return false;
    dw_fac_->CreateTextFormat(L"Verdana", nullptr,
                              DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL,
                              DWRITE_FONT_STRETCH_NORMAL, 12.0f, L"en-us", &dw_fmt_);
    dw_fmt_->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
    return true;
}

bool Overlay::CreateSwapAndTarget() {
    DXGI_SWAP_CHAIN_DESC1 sd{};
    sd.Width            = width_;
    sd.Height           = height_;
    sd.Format           = DXGI_FORMAT_B8G8R8A8_UNORM;
    sd.BufferCount      = 2;
    sd.BufferUsage      = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.SwapEffect       = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    sd.AlphaMode        = DXGI_ALPHA_MODE_PREMULTIPLIED;
    sd.SampleDesc.Count = 1;

    if (FAILED(fac_->CreateSwapChainForComposition(dxgi_.Get(), &sd, nullptr, &swap_))) return false;

    if (FAILED(DCompositionCreateDevice(dxgi_.Get(), IID_PPV_ARGS(&dcomp_)))) return false;
    if (FAILED(dcomp_->CreateTargetForHwnd(hwnd_, TRUE, &dcomp_tgt_))) return false;
    if (FAILED(dcomp_->CreateVisual(&dcomp_vis_))) return false;
    dcomp_vis_->SetContent(swap_.Get());
    dcomp_tgt_->SetRoot(dcomp_vis_.Get());
    dcomp_->Commit();

    ComPtr<IDXGISurface2> surf;
    if (FAILED(swap_->GetBuffer(0, IID_PPV_ARGS(&surf)))) return false;
    D2D1_BITMAP_PROPERTIES1 bp{};
    bp.pixelFormat    = D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED);
    bp.bitmapOptions  = D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW;
    bp.dpiX = bp.dpiY = 96.0f;
    if (FAILED(d2d_->CreateBitmapFromDxgiSurface(surf.Get(), &bp, &d2d_tgt_))) return false;
    d2d_->SetTarget(d2d_tgt_.Get());

    d2d_->CreateSolidColorBrush(D2D1::ColorF(D2D1::ColorF::White), &brush_);
    return true;
}

void Overlay::Resize(int w, int h) {
    if (w == width_ && h == height_) return;
    if (w < 32 || h < 32) return;
    d2d_->SetTarget(nullptr);
    d2d_tgt_.Reset();
    swap_->ResizeBuffers(2, w, h, DXGI_FORMAT_B8G8R8A8_UNORM, 0);
    width_ = w; height_ = h;
    ComPtr<IDXGISurface2> surf;
    swap_->GetBuffer(0, IID_PPV_ARGS(&surf));
    D2D1_BITMAP_PROPERTIES1 bp{};
    bp.pixelFormat    = D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED);
    bp.bitmapOptions  = D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW;
    bp.dpiX = bp.dpiY = 96.0f;
    d2d_->CreateBitmapFromDxgiSurface(surf.Get(), &bp, &d2d_tgt_);
    d2d_->SetTarget(d2d_tgt_.Get());
}

void Overlay::FollowGame() {
    if (game_title_.empty()) return;
    if (!game_ || !IsWindow(game_)) {
        game_ = FindWindowW(nullptr, game_title_.c_str());
        if (!game_) return;
    }
    RECT cr;
    if (!GetClientRect(game_, &cr)) return;
    POINT tl{ cr.left, cr.top };
    ClientToScreen(game_, &tl);
    int w = cr.right - cr.left;
    int h = cr.bottom - cr.top;
    if (w < 32 || h < 32) return;
    SetWindowPos(hwnd_, HWND_TOPMOST, tl.x, tl.y, w, h,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);
    Resize(w, h);
}

bool Overlay::Pump() {
    MSG msg;
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT) return false;
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    FollowGame();
    return true;
}

void Overlay::BeginFrame() {
    d2d_->BeginDraw();
    d2d_->Clear(D2D1::ColorF(0.f, 0.f, 0.f, 0.f));
}

void Overlay::EndFrame() {
    d2d_->EndDraw();
    swap_->Present(1, 0);
}

void Overlay::DrawLine(float x1, float y1, float x2, float y2, Color c, float t) {
    brush_->SetColor(c.d2d());
    d2d_->DrawLine(D2D1::Point2F(x1, y1), D2D1::Point2F(x2, y2), brush_.Get(), t);
}
void Overlay::DrawRect(float x, float y, float w, float h, Color c, float t) {
    brush_->SetColor(c.d2d());
    d2d_->DrawRectangle(D2D1::RectF(x, y, x+w, y+h), brush_.Get(), t);
}
void Overlay::DrawFilledRect(float x, float y, float w, float h, Color c) {
    brush_->SetColor(c.d2d());
    d2d_->FillRectangle(D2D1::RectF(x, y, x+w, y+h), brush_.Get());
}
void Overlay::DrawCorneredBox(float x, float y, float w, float h, Color c, float t) {
    brush_->SetColor(c.d2d());
    float L = (w < h ? w : h) * 0.25f;
    auto P = [](float a, float b){ return D2D1::Point2F(a, b); };
    d2d_->DrawLine(P(x,y),       P(x+L,y),     brush_.Get(), t);
    d2d_->DrawLine(P(x,y),       P(x,y+L),     brush_.Get(), t);
    d2d_->DrawLine(P(x+w,y),     P(x+w-L,y),   brush_.Get(), t);
    d2d_->DrawLine(P(x+w,y),     P(x+w,y+L),   brush_.Get(), t);
    d2d_->DrawLine(P(x,y+h),     P(x+L,y+h),   brush_.Get(), t);
    d2d_->DrawLine(P(x,y+h),     P(x,y+h-L),   brush_.Get(), t);
    d2d_->DrawLine(P(x+w,y+h),   P(x+w-L,y+h), brush_.Get(), t);
    d2d_->DrawLine(P(x+w,y+h),   P(x+w,y+h-L), brush_.Get(), t);
}
void Overlay::DrawCircle(float x, float y, float r, Color c, float t) {
    brush_->SetColor(c.d2d());
    d2d_->DrawEllipse(D2D1::Ellipse(D2D1::Point2F(x, y), r, r), brush_.Get(), t);
}
void Overlay::DrawFilledCircle(float x, float y, float r, Color c) {
    brush_->SetColor(c.d2d());
    d2d_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(x, y), r, r), brush_.Get());
}
void Overlay::DrawText(float x, float y, const wchar_t* text, Color c, float size, bool centered, bool outline) {
    if (!text || !*text) return;
    ComPtr<IDWriteTextFormat> fmt;
    dw_fac_->CreateTextFormat(L"Verdana", nullptr, DWRITE_FONT_WEIGHT_BOLD,
                              DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
                              size, L"en-us", &fmt);
    fmt->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
    ComPtr<IDWriteTextLayout> layout;
    dw_fac_->CreateTextLayout(text, (UINT32)wcslen(text), fmt.Get(), 2000.0f, 2000.0f, &layout);
    DWRITE_TEXT_METRICS tm; layout->GetMetrics(&tm);
    float dx = centered ? (x - tm.width * 0.5f) : x;
    if (outline) {
        brush_->SetColor(D2D1::ColorF(0, 0, 0, 1.0f));
        const int off[4][2] = { {-1,0}, {1,0}, {0,-1}, {0,1} };
        for (auto& o : off)
            d2d_->DrawTextLayout(D2D1::Point2F(dx + o[0], y + o[1]), layout.Get(), brush_.Get());
    }
    brush_->SetColor(c.d2d());
    d2d_->DrawTextLayout(D2D1::Point2F(dx, y), layout.Get(), brush_.Get());
}
void Overlay::DrawHealthBar(float x, float y, float w, float h, float ratio, bool vertical) {
    if (ratio < 0) ratio = 0; if (ratio > 1) ratio = 1;
    DrawFilledRect(x, y, w, h, Color(0, 0, 0, 0.65f));
    Color c(1.f - ratio, ratio, 0.0f, 1.0f);
    if (vertical) {
        float fill = (h - 2) * ratio;
        DrawFilledRect(x + 1, y + (h - 1 - fill), w - 2, fill, c);
    } else {
        DrawFilledRect(x + 1, y + 1, (w - 2) * ratio, h - 2, c);
    }
    DrawRect(x, y, w, h, Color(0, 0, 0, 1), 1.0f);
}
void Overlay::DrawShieldBar(float x, float y, float w, float h, float ratio, bool vertical) {
    if (ratio < 0) ratio = 0; if (ratio > 1) ratio = 1;
    DrawFilledRect(x, y, w, h, Color(0, 0, 0, 0.65f));
    Color c(0.3f, 0.7f, 1.0f, 1.0f);
    if (vertical) {
        float fill = (h - 2) * ratio;
        DrawFilledRect(x + 1, y + (h - 1 - fill), w - 2, fill, c);
    } else {
        DrawFilledRect(x + 1, y + 1, (w - 2) * ratio, h - 2, c);
    }
    DrawRect(x, y, w, h, Color(0, 0, 0, 1), 1.0f);
}

void Overlay::Destroy() {
    d2d_.Reset(); d2d_tgt_.Reset(); d2d_dev_.Reset(); d2d_fac_.Reset();
    dcomp_vis_.Reset(); dcomp_tgt_.Reset(); dcomp_.Reset();
    swap_.Reset(); dxgi_.Reset(); fac_.Reset();
    ctx_.Reset(); d3d_.Reset();
    if (hwnd_) { DestroyWindow(hwnd_); hwnd_ = nullptr; }
}
