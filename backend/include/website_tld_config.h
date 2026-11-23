#pragma once

#include "app.h"
#include <set>

namespace website_inspector::config {
inline const std::set<S> ApprovedTlds = {
    ".com", ".in", ".org", ".net", ".edu", ".gov", ".co",
    ".uk",  ".ca", ".au",  ".de",  ".jp",  ".io"};
inline constexpr int UnapprovedTldRiskPoints = 51;
} // namespace website_inspector::config
