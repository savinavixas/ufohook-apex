#pragma once
#include "overlay.h"
#include <vector>
#include <string>
#include <functional>

enum class ItemType { Header, Toggle, Slider, Combo, Button, ColorBtn };

struct MenuItem {
    ItemType type;
    std::wstring label;
    bool*       toggle = nullptr;
    float*      f_val  = nullptr;
    int*        i_val  = nullptr;
    float       f_min  = 0, f_max = 1;
    std::vector<std::wstring> combo;
    Color*      col    = nullptr;
    std::function<void()> onClick;
};

class Menu {
public:
    void BindToggleKey(int vk) { toggle_vk_ = vk; }
    void SetTitle(const std::wstring& s) { title_ = s; }
    void SetAccent(Color c)              { accent_ = c; }
    void SetVisible(bool v)              { visible_ = v; }
    bool IsVisible() const               { return visible_; }

    void AddHeader(const std::wstring& label);
    void AddToggle(const std::wstring& label, bool* v);
    void AddSlider(const std::wstring& label, float* v, float lo, float hi);
    void AddIntSlider(const std::wstring& label, int* v, int lo, int hi);
    void AddCombo(const std::wstring& label, int* v, std::vector<std::wstring> opts);
    void AddButton(const std::wstring& label, std::function<void()> cb);
    void AddColor(const std::wstring& label, Color* c);

    void Tick();
    void Draw(Overlay& o);

private:
    bool EdgeKey(int vk);
    void MoveSelection(int dir);

    std::wstring title_   = L"UFOHook  ::  ESP";
    Color        accent_  { 1.0f, 0.25f, 0.35f, 1.0f };
    bool         visible_ = true;
    int          toggle_vk_ = VK_INSERT;
    int          selected_ = 0;
    float        x_ = 60.f, y_ = 60.f, w_ = 320.f;
    bool         last_[256] = {};
    std::vector<MenuItem> items_;
    int color_edit_idx_ = -1;
    int color_edit_channel_ = 0;
};
