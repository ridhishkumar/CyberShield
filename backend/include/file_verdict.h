#pragma once
#include "app.h"
#include <optional>

enum class Verdict { noDetection, detected, policyBlocked };
std::optional<Verdict> windowsVerdict(const S &bytes, const wchar_t *name);
J authenticodeAssessment(const S &bytes);
