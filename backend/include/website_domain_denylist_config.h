#pragma once

#include "app.h"
#include <set>

namespace website_inspector::config {
// Add only reviewed hostnames. Each entry also matches its subdomains.
inline const std::set<S> StrictlyDeniedDomains = {};
} // namespace website_inspector::config
