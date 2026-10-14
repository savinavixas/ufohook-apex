#pragma once
#include "overlay.h"
#include <vector>

struct Vec3 { float x, y, z; };
struct Vec2 { float x, y; };

struct ViewMatrix { float m[4][4]; };

struct Entity {
    Vec3  head;
    Vec3  feet;
    float health = 100.f;
    float max_health = 100.f;
    float shield = 0.f;
    float max_shield = 100.f;
    float distance = 0.f;
    bool  visible = false;
    int   team = -1;
    const wchar_t* name = L"";
    const wchar_t* weapon = nullptr;
    std::vector<Vec3> bones;
};

struct ESPConfig {
    bool  enabled      = true;
    bool  box          = true;
    int   box_style    = 0;
    bool  snap_lines   = false;
    bool  skeleton     = false;
    bool  name         = true;
    bool  distance     = true;
    bool  weapon       = false;
    bool  health_bar   = true;
    bool  shield_bar   = true;
    bool  team_check   = true;
    bool  visibility_check = false;
    float max_distance = 300.0f;
    Color col_visible   { 0.9f, 1.0f, 0.3f, 1.0f };
    Color col_occluded  { 1.0f, 0.3f, 0.3f, 1.0f };
    Color col_name      { 1.0f, 1.0f, 1.0f, 1.0f };
    Color col_distance  { 0.75f, 0.9f, 1.0f, 1.0f };
    Color col_skeleton  { 1.0f, 1.0f, 1.0f, 0.9f };
    Color col_snap      { 1.0f, 0.4f, 0.4f, 0.75f };
};

bool WorldToScreen(const ViewMatrix& vm, const Vec3& w, Vec2& out, int sw, int sh);
void DrawEntity(Overlay& o, const Entity& e, const ESPConfig& cfg,
                const ViewMatrix& vm, int local_team);
