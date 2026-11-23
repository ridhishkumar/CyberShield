#pragma once

#include "app.h"
#include <map>
#include <vector>

namespace website_inspector {
struct ParsedUrl {
  S url;
  S scheme;
  S host;
  S port;
  S path;
  bool isIp = false;
  bool hasUserInfo = false;
};

struct Finding {
  S id;
  S module;
  S family;
  S severity;
  S text;
  S evidence;
  int points = 0;
  int reliability = 80;
};

struct ScoreResult {
  int score = 0;
  int categorySubtotal = 0;
  int corroborationBonus = 0;
  int independentCategories = 0;
  std::map<S, int> categoryPoints;
};

struct TldAssessment {
  S suffix;
  bool approved = false;
  int riskPoints = 0;
};

bool parseUrl(const S &input, ParsedUrl &parsed, S &error);
bool isPublicAddress(const S &address);
TldAssessment assessTld(const S &hostname);
ScoreResult scoreFindings(const std::vector<Finding> &findings);
J inspectHtml(const S &html, const S &baseUrl);
J inspectWebsite(const J &input);
}
