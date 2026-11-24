#include "website_inspector.h"
#include "website_tld_config.h"

#include <cctype>

namespace website_inspector {
namespace {
S normalizeHostname(S host) {
  for (char &c : host)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  while (!host.empty() && host.back() == '.')
    host.pop_back();
  return host;
}
} // namespace

TldAssessment assessTld(const S &hostname) {
  const S host = normalizeHostname(hostname);
  const auto separator = host.rfind('.');
  const S suffix = separator == S::npos ? S() : host.substr(separator);
  const bool approved = config::ApprovedTlds.count(suffix) != 0;
  return {suffix, approved,
          approved ? 0 : config::UnapprovedTldRiskPoints};
}

bool isStrictlyDeniedHost(const S &hostname,
                          const std::set<S> &denylist) {
  const S host = normalizeHostname(hostname);
  if (host.empty())
    return false;

  for (const S &entry : denylist) {
    const S deniedHost = normalizeHostname(entry);
    if (deniedHost.empty())
      continue;
    if (host == deniedHost)
      return true;
    if (host.size() > deniedHost.size() &&
        host.compare(host.size() - deniedHost.size(), deniedHost.size(),
                     deniedHost) == 0 &&
        host[host.size() - deniedHost.size() - 1] == '.')
      return true;
  }
  return false;
}
} // namespace website_inspector
