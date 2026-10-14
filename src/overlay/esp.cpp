#include "esp.h"
#include <cwchar>
#include <cstdio>

bool WorldToScreen(const ViewMatrix& vm, const Vec3& w, Vec2& out, int sw, int sh) {
    float cx = w.x * vm.m[0][0] + w.y * vm.m[0][1] + w.z * vm.m[0][2] + vm.m[0][3];
    float cy = w.x * vm.m[1][0] + w.y * vm.m[1][1] + w.z * vm.m[1][2] + vm.m[1][3];
    float cw = w.x * vm.m[3][0] + w.y * vm.m[3][1] + w.z * vm.m[3][2] + vm.m[3][3];
    if (cw < 0.01f) return false;
    float ndcX = cx / cw;
    float ndcY = cy / cw;
    out.x = (sw * 0.5f) + (ndcX * sw * 0.5f);
    out.y = (sh * 0.5f) - (ndcY * sh * 0.5f);
    return true;
}

void DrawEntity(Overlay& o, const Entity& e, const ESPConfig& cfg,
                const ViewMatrix& vm, int local_team)
{
    if (!cfg.enabled) return;
    if (e.distance > cfg.max_distance) return;
    if (cfg.team_check && local_team >= 0 && e.team == local_team) return;
    if (cfg.visibility_check && !e.visible) return;

    int sw = o.Width(), sh = o.Height();
    Vec2 shead{}, sfeet{};
    if (!WorldToScreen(vm, e.head, shead, sw, sh)) return;
    if (!WorldToScreen(vm, e.feet, sfeet, sw, sh)) return;

    float ht = sfeet.y - shead.y;
    if (ht < 4) return;
    float wd = ht * 0.42f;
    float bx = shead.x - wd * 0.5f;
    float by = shead.y - ht * 0.08f;

    Color box_col = e.visible ? cfg.col_visible : cfg.col_occluded;

    if (cfg.box) {
        if (cfg.box_style == 0)       o.DrawRect(bx, by, wd, ht, box_col, 1.4f);
        else if (cfg.box_style == 1)  o.DrawCorneredBox(bx, by, wd, ht, box_col, 1.6f);
        else {
            o.DrawFilledRect(bx, by, wd, ht, Color(box_col.r, box_col.g, box_col.b, 0.08f));
            o.DrawRect(bx, by, wd, ht, box_col, 1.0f);
        }
    }

    if (cfg.health_bar && e.max_health > 0) {
        float r = e.health / e.max_health;
        o.DrawHealthBar(bx - 7, by, 4, ht, r, true);
    }
    if (cfg.shield_bar && e.max_shield > 0) {
        float r = e.shield / e.max_shield;
        o.DrawShieldBar(bx - 13, by, 4, ht, r, true);
    }

    if (cfg.snap_lines) {
        o.DrawLine(sw * 0.5f, (float)sh, shead.x, shead.y, cfg.col_snap, 1.2f);
    }

    if (cfg.skeleton && !e.bones.empty()) {
        for (size_t i = 0; i + 1 < e.bones.size(); i += 2) {
            Vec2 a, b;
            if (WorldToScreen(vm, e.bones[i], a, sw, sh) &&
                WorldToScreen(vm, e.bones[i+1], b, sw, sh))
                o.DrawLine(a.x, a.y, b.x, b.y, cfg.col_skeleton, 1.2f);
        }
    }

    float ty = by - 16;
    if (cfg.name && e.name && *e.name) {
        o.DrawText(bx + wd * 0.5f, ty, e.name, cfg.col_name, 11.f, true, true);
        ty -= 14;
    }
    if (cfg.weapon && e.weapon && *e.weapon) {
        o.DrawText(bx + wd * 0.5f, by + ht + 2, e.weapon,
                   Color(1, 1, 0.5f, 1), 10.f, true, true);
    }
    if (cfg.distance) {
        wchar_t buf[32];
        swprintf_s(buf, L"[%.0fm]", e.distance);
        o.DrawText(bx + wd * 0.5f, by + ht + 14, buf, cfg.col_distance, 10.f, true, true);
    }
}
