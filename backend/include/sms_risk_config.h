#pragma once

namespace sms_risk::config {
inline constexpr int LinkWeight = 30;
inline constexpr int SenderWeight = 25;
inline constexpr int ActionWeight = 20;
inline constexpr int UrgencyWeight = 15;
inline constexpr int ContextWeight = 10;

inline constexpr int CautionThreshold = 36;
inline constexpr int SuspiciousThreshold = 61;
inline constexpr int HighRiskThreshold = 61;
inline constexpr int MaximumInteractionBonus = 36;

inline constexpr int UrgencyActionInteractionWeight = 45;
inline constexpr int LinkActionInteractionWeight = 14;
inline constexpr int LinkSenderInteractionWeight = 12;
inline constexpr int SenderActionInteractionWeight = 10;

static_assert(LinkWeight + SenderWeight + ActionWeight + UrgencyWeight +
                  ContextWeight ==
              100);
static_assert(CautionThreshold < SuspiciousThreshold &&
              SuspiciousThreshold == HighRiskThreshold);
} // namespace sms_risk::config
