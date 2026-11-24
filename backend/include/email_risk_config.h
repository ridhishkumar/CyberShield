#pragma once

namespace email_risk::config {
inline constexpr int UrgencyWeight = 20;
inline constexpr int LinkWeight = 25;
inline constexpr int SenderWeight = 15;
inline constexpr int FinancialWeight = 25;
inline constexpr int ContentWeight = 15;

inline constexpr int CautionThreshold = 20;
inline constexpr int SuspiciousThreshold = 40;
inline constexpr int HighRiskThreshold = 70;
inline constexpr int MaximumInteractionBonus = 18;
inline constexpr int UrgencyFinancialInteractionWeight = 22;
inline constexpr int LinkSenderInteractionWeight = 16;
inline constexpr int LinkFinancialInteractionWeight = 18;
inline constexpr int UrgencyLinkInteractionWeight = 16;
inline constexpr int UrgencyContentInteractionWeight = 18;
inline constexpr int FinancialContentInteractionWeight = 20;
inline constexpr int SenderFinancialInteractionWeight = 12;
inline constexpr int SenderContentInteractionWeight = 10;
inline constexpr int LinkContentInteractionWeight = 12;
} // namespace email_risk::config
