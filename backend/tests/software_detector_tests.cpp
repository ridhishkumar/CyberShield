#include "app.h"
#include <cctype>
#include <stdexcept>

S lower(S value) {
  for (char &c : value)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return value;
}

S field(const J &input, const S &name, size_t max, bool required) {
  const auto found = input.find(name);
  if (found == input.end() || found->is_null()) {
    if (required)
      throw Problem(400, "Missing field.");
    return {};
  }
  if (!found->is_string())
    throw Problem(400, "Invalid field.");
  S value = found->get<S>();
  if (value.size() > max)
    throw Problem(400, "Field too long.");
  return value;
}

static J scan(const S &name, const S &url = "", const S &publisher = "") {
  return analyze("Software",
                 {{"name", name}, {"url", url}, {"publisher", publisher}});
}

int main() {
  const J unknown = scan("Unlisted Utility");
  if (unknown["score"] != 10 || !unknown["trust_score"].is_null() ||
      unknown["category"] != "Insufficient information")
    throw std::runtime_error("Unknown software must not receive a trust score.");

  const J nameOnly = scan("VLC");
  if (nameOnly["score"] != 10 || !nameOnly["trust_score"].is_null() ||
      nameOnly["category"] != "Insufficient information")
    throw std::runtime_error("A product name alone must remain unverified.");

  const J officialVersioned = scan(
      "VLC media player 3.0.20 x64 installer",
      "https://www.videolan.org/vlc/", "VideoLAN");
  if (officialVersioned["score"] != 0 ||
      !officialVersioned["trust_score"].is_null() ||
      officialVersioned["category"] != "Listed source")
    throw std::runtime_error("Official versioned VLC source did not match.");

  const J lookalike = scan("VLC 3.0.20",
                           "https://videolan.org.evil.test/vlc",
                           "Fake Publisher LLC");
  if (lookalike["score"].get<int>() < 60 ||
      !lookalike["trust_score"].is_null() ||
      lookalike["category"] != "High risk")
    throw std::runtime_error("Impersonating source was not rated high risk.");

  const J brandedLookalike =
      scan("Google Chrome 138", "https://google-chrome-login.xyz/login");
  if (brandedLookalike["score"].get<int>() < 60 ||
      brandedLookalike["category"] != "High risk")
    throw std::runtime_error("Branded fake login source was not rated high risk.");

  const J crack = scan("VLC cracked installer");
  if (crack["score"].get<int>() < 40 || !crack["trust_score"].is_null() ||
      crack["category"] != "Suspicious")
    throw std::runtime_error("Cracked software indicator was not detected.");
}
