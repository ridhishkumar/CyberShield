#pragma once

namespace software_risk::config {
inline constexpr int SourceDomainWeight = 20;
inline constexpr int FileAuthenticityWeight = 25;
inline constexpr int FileCharacteristicsWeight = 15;
inline constexpr int RedirectWeight = 5;
inline constexpr int ThreatIntelligenceWeight = 0;
inline constexpr int PublisherConsistencyWeight = 35;

inline constexpr int SafeMaximum = 35;
inline constexpr int CautionThreshold = 36;
inline constexpr int HighRiskThreshold = 61;

static_assert(SourceDomainWeight + FileAuthenticityWeight +
                  FileCharacteristicsWeight + RedirectWeight +
                  ThreatIntelligenceWeight + PublisherConsistencyWeight ==
              100);
static_assert(CautionThreshold == SafeMaximum + 1 &&
              CautionThreshold < HighRiskThreshold);
} // namespace software_risk::config
