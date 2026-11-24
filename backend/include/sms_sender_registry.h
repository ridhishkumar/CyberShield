#pragma once
#include "app.h"
#include "sms_risk_config.h"

struct SmsOrganization {
  S name;
  std::vector<S> senderIds;
  std::vector<S> phoneNumbers;
  std::vector<S> officialDomains;
  S reference;
  std::vector<S> aliases = {};
};

inline const std::vector<SmsOrganization> &smsOrganizationRegistry() {
  // The source lists call/IVR numbers, not verified SMS origin identifiers.
  static const std::vector<SmsOrganization> organizations = {
      {"ICICI Bank",
       {},
       {},
       {"icicibank.com", "icici.bank.in"},
       "https://www.icici.bank.in/customer-care",
       {"ICICI", "iMobile Pay"}}};
  return organizations;
}

inline constexpr int SmsSuspiciousThreshold =
    sms_risk::config::SuspiciousThreshold;
inline constexpr int SmsHighRiskThreshold = sms_risk::config::HighRiskThreshold;
