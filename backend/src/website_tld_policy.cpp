#include "website_inspector.h"
#include "website_tld_config.h"

#include <cctype>

namespace website_inspector {
TldAssessment assessTld(const S &hostname) {
  S host = hostname;
  for (char &c : host)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  while (!host.empty() && host.back() == '.')
    host.pop_back();

  const auto separator = host.rfind('.');
  const S suffix = separator == S::npos ? S() : host.substr(separator);
  const bool approved = config::ApprovedTlds.count(suffix) != 0;
  return {suffix, approved,
          approved ? 0 : config::UnapprovedTldRiskPoints};
}
} // namespace website_inspector
