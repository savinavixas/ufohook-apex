#include "menu.h"
#include <Windows.h>
#include <cstdio>

bool Menu::EdgeKey(int vk) {
    bool now = (GetAsyncKeyState(vk) & 0x8000) != 0;
    bool edge = now && !last_[vk];
    last_[vk] = now;
    return edge;
}

void Menu::AddHeader(const std::wstring& l)             { items_.push_back({ ItemType::Header, l }); }
void Menu::AddToggle(const std::wstring& l, bool* v)    { items_.push_back({ ItemType::Toggle, l, v }); }
void Menu::AddSlider(const std::wstring& l, float* v, float a, float b) {
    MenuItem it{ ItemType::Slider, l }; it.f_val = v; it.f_min = a; it.f_max = b;
    items_.push_back(std::move(it));
}
void Menu::AddIntSlider(const std::wstring& l, int* v, int a, int b) {
    MenuItem it{ ItemType::Slider, l }; it.i_val = v; it.f_min = (float)a; it.f_max = (float)b;
    items_.push_back(std::move(it));
}
void Menu::AddCombo(const std::wstring& l, int* v, std::vector<std::wstring> opts) {
    MenuItem it{ ItemType::Combo, l }; it.i_val = v; it.combo = std::move(opts);
    items_.push_back(std::move(it));
}
void Menu::AddButton(const std::wstring& l, std::function<void()> cb) {
    MenuItem it{ ItemType::Button, l }; it.onClick = std::move(cb);
    items_.push_back(std::move(it));
}
void Menu::AddColor(const std::wstring& l, Color* c) {
    MenuItem it{ ItemType::ColorBtn, l }; it.col = c;
    items_.push_back(std::move(it));
}

void Menu::MoveSelection(int dir) {
    int n = (int)items_.size();
    if (n == 0) return;
    for (int i = 0; i < n; ++i) {
        selected_ = (selected_ + dir + n) % n;
        if (items_[selected_].type != ItemType::Header) break;
    }
}

void Menu::Tick() {
    if (EdgeKey(toggle_vk_)) visible_ = !visible_;
    if (!visible_ || items_.empty()) return;

    if (color_edit_idx_ >= 0) {
        if (EdgeKey(VK_ESCAPE)) { color_edit_idx_ = -1; return; }
        if (EdgeKey(VK_TAB))    color_edit_channel_ = (color_edit_channel_ + 1) & 3;
        Color* c = items_[color_edit_idx_].col;
        float* ch = (color_edit_channel_ == 0) ? &c->r :
                    (color_edit_channel_ == 1) ? &c->g :
                    (color_edit_channel_ == 2) ? &c->b : &c->a;
        if (GetAsyncKeyState(VK_LEFT)  & 0x8000) *ch = max(0.f, *ch - 0.01f);
        if (GetAsyncKeyState(VK_RIGHT) & 0x8000) *ch = min(1.f, *ch + 0.01f);
        return;
    }

    if (EdgeKey(VK_UP))   MoveSelection(-1);
    if (EdgeKey(VK_DOWN)) MoveSelection(+1);

    MenuItem& it = items_[selected_];
    switch (it.type) {
    case ItemType::Toggle:
        if (EdgeKey(VK_RETURN) || EdgeKey(VK_SPACE)) *it.toggle = !*it.toggle;
        break;
    case ItemType::Button:
        if (EdgeKey(VK_RETURN) || EdgeKey(VK_SPACE)) if (it.onClick) it.onClick();
        break;
    case ItemType::Slider: {
        float step = (it.f_max - it.f_min) * 0.01f;
        bool fast = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        if (fast) step *= 5.f;
        if (GetAsyncKeyState(VK_LEFT) & 0x8000) {
            if (it.f_val) *it.f_val = max(it.f_min, *it.f_val - step);
            if (it.i_val) *it.i_val = max((int)it.f_min, *it.i_val - (fast?5:1));
        }
        if (GetAsyncKeyState(VK_RIGHT) & 0x8000) {
            if (it.f_val) *it.f_val = min(it.f_max, *it.f_val + step);
            if (it.i_val) *it.i_val = min((int)it.f_max, *it.i_val + (fast?5:1));
        }
    } break;
    case ItemType::Combo:
        if (EdgeKey(VK_LEFT))  *it.i_val = (*it.i_val - 1 + (int)it.combo.size()) % (int)it.combo.size();
        if (EdgeKey(VK_RIGHT)) *it.i_val = (*it.i_val + 1) % (int)it.combo.size();
        break;
    case ItemType::ColorBtn:
        if (EdgeKey(VK_RETURN) || EdgeKey(VK_SPACE)) { color_edit_idx_ = selected_; color_edit_channel_ = 0; }
        break;
    default: break;
    }
}

void Menu::Draw(Overlay& o) {
    if (!visible_) return;

    float rowH = 22.f;
    float headerH = 32.f;
    float h = headerH + 8.f + items_.size() * rowH + 8.f;

    o.DrawFilledRect(x_, y_, w_, h, Color(0.05f, 0.05f, 0.07f, 0.9f));
    o.DrawRect(x_, y_, w_, h, accent_, 1.5f);
    o.DrawFilledRect(x_, y_, w_, headerH, Color(accent_.r*0.6f, accent_.g*0.2f, accent_.b*0.3f, 0.95f));
    o.DrawFilledRect(x_, y_ + headerH - 2, w_, 2, accent_);
    o.DrawText(x_ + 12, y_ + 8, title_.c_str(), Color(1, 1, 1, 1), 14.f, false, false);

    float yy = y_ + headerH + 6.f;
    for (int i = 0; i < (int)items_.size(); ++i) {
        MenuItem& it = items_[i];

        if (it.type == ItemType::Header) {
            o.DrawFilledRect(x_ + 4, yy + rowH*0.5f - 1, w_ - 8, 1, Color(accent_.r, accent_.g, accent_.b, 0.4f));
            o.DrawText(x_ + 12, yy + 3, it.label.c_str(),
                       Color(accent_.r, accent_.g, accent_.b, 1.f), 10.f, false, false);
            yy += rowH; continue;
        }

        if (i == selected_) {
            o.DrawFilledRect(x_ + 4, yy, w_ - 8, rowH - 2,
                             Color(accent_.r, accent_.g, accent_.b, 0.22f));
            o.DrawFilledRect(x_ + 4, yy, 2, rowH - 2, accent_);
        }
        o.DrawText(x_ + 14, yy + 4, it.label.c_str(), Color(0.95f, 0.95f, 0.95f, 1), 12.f, false, false);

        wchar_t buf[64]{};
        float rhs_x = x_ + w_ - 14.f;
        switch (it.type) {
        case ItemType::Toggle: {
            const wchar_t* s = *it.toggle ? L"ON" : L"OFF";
            Color c = *it.toggle ? Color(0.4f, 1.f, 0.5f, 1.f) : Color(0.5f, 0.5f, 0.5f, 1.f);
            o.DrawText(rhs_x - 24, yy + 4, s, c, 12.f, false, false);
        } break;
        case ItemType::Slider: {
            if (it.f_val) swprintf_s(buf, L"%.2f", *it.f_val);
            else          swprintf_s(buf, L"%d",   *it.i_val);
            o.DrawText(rhs_x - 32, yy + 4, buf, Color(0.9f, 0.9f, 1.f, 1), 12.f, false, false);
            float trackY = yy + rowH - 4;
            float trackW = w_ - 24;
            o.DrawFilledRect(x_ + 12, trackY, trackW, 2, Color(0.3f, 0.3f, 0.35f, 1));
            float v = it.f_val ? *it.f_val : (float)*it.i_val;
            float t = (v - it.f_min) / (it.f_max - it.f_min);
            if (t < 0) t = 0; if (t > 1) t = 1;
            o.DrawFilledRect(x_ + 12, trackY, trackW * t, 2, accent_);
        } break;
        case ItemType::Combo:
            if (it.i_val && !it.combo.empty())
                o.DrawText(rhs_x - 60, yy + 4,
                           it.combo[*it.i_val % it.combo.size()].c_str(),
                           Color(0.85f, 0.85f, 1.f, 1), 12.f, false, false);
            break;
        case ItemType::Button:
            o.DrawText(rhs_x - 30, yy + 4, L"[GO]", accent_, 12.f, false, false);
            break;
        case ItemType::ColorBtn:
            if (it.col) {
                o.DrawFilledRect(rhs_x - 50, yy + 3, 44, rowH - 8, *it.col);
                o.DrawRect(rhs_x - 50, yy + 3, 44, rowH - 8, Color(0, 0, 0, 1), 1.f);
            }
            break;
        default: break;
        }
        yy += rowH;
    }

    if (color_edit_idx_ >= 0 && items_[color_edit_idx_].col) {
        Color* c = items_[color_edit_idx_].col;
        float px = x_ + w_ + 10, py = y_;
        float pw = 180, ph = 160;
        o.DrawFilledRect(px, py, pw, ph, Color(0.05f, 0.05f, 0.07f, 0.95f));
        o.DrawRect(px, py, pw, ph, accent_, 1.5f);
        o.DrawText(px + 10, py + 8, L"Color  (TAB chan, L/R)", Color(1,1,1,1), 11, false, false);
        const wchar_t* names[4] = { L"R", L"G", L"B", L"A" };
        float vals[4] = { c->r, c->g, c->b, c->a };
        for (int i = 0; i < 4; ++i) {
            float ry = py + 32.f + i * 24.f;
            bool sel = (i == color_edit_channel_);
            o.DrawText(px + 12, ry, names[i], sel ? accent_ : Color(0.8f,0.8f,0.8f,1), 12, false, false);
            o.DrawFilledRect(px + 32, ry + 6, 100, 4, Color(0.2f, 0.2f, 0.25f, 1));
            o.DrawFilledRect(px + 32, ry + 6, 100 * vals[i], 4, accent_);
            wchar_t b2[16]; swprintf_s(b2, L"%.2f", vals[i]);
            o.DrawText(px + 140, ry, b2, Color(1,1,1,1), 12, false, false);
        }
        o.DrawFilledRect(px + 12, py + ph - 20, pw - 24, 10, *c);
    }
}
