#include "website_inspector.h"
#include "website_domain_denylist_config.h"
#include <cassert>

#undef assert
#define assert(condition)                                                    \
  do {                                                                       \
    if (!(condition))                                                        \
      throw std::runtime_error("Test assertion failed: " #condition);       \
  } while (false)

std::filesystem::path root;

int main() {
  website_inspector::ParsedUrl parsed;
  S error;
  assert(website_inspector::parseUrl("example.org/path?q=1", parsed, error));
  assert(parsed.scheme == "https");
  assert(parsed.host == "example.org");
  assert(parsed.port == "443");
  assert(parsed.url.find("/path?q=1") != S::npos);

  assert(!website_inspector::parseUrl("javascript:alert(1)", parsed, error));
  assert(!website_inspector::parseUrl("https://example.org\\@127.0.0.1", parsed,
                                      error));
  assert(website_inspector::parseUrl(
      "https://user:secret@example.org/private", parsed, error));
  assert(parsed.hasUserInfo);
  assert(parsed.url.find("secret") == S::npos);

  assert(website_inspector::isPublicAddress("8.8.8.8"));
  assert(website_inspector::isPublicAddress("2001:4860:4860::8888"));
  assert(!website_inspector::isPublicAddress("127.0.0.1"));
  assert(!website_inspector::isPublicAddress("10.2.3.4"));
  assert(!website_inspector::isPublicAddress("169.254.169.254"));
  assert(!website_inspector::isPublicAddress("192.0.2.1"));
  assert(!website_inspector::isPublicAddress("::1"));
  assert(!website_inspector::isPublicAddress("fc00::1"));

  for (const auto &boundary :
       std::map<int, S>{{0, "Safe"}, {35, "Safe"}, {36, "Be Cautious"},
                        {60, "Be Cautious"}, {61, "Highly Risky"},
                        {100, "Highly Risky"}})
    assert(website_inspector::categoryForScore(boundary.first) ==
           boundary.second);

  const J blocked =
      website_inspector::inspectWebsite({{"url", "http://127.0.0.1"}});
  assert(blocked["category"] == "Unable to Verify");
  assert(blocked["score"].is_null());
  assert(blocked["observed_score"] == 18);
  assert(blocked["scoring"]["observed_total"] == 18);
  assert(blocked["scoring"]["observed_scope"] == "incomplete_inspection");
  assert(blocked["checks"][1]["status"] == "blocked");
  assert(blocked["checks"][3]["status"] == "blocked");
  assert(blocked["scoring"]["total"].is_null());
  assert(blocked["indicator_coverage"].size() >= 20);
  assert(blocked["indicator_coverage"][6]["status"] == "not_checked");
  const std::set<S> loopbackDenylist = {"127.0.0.1"};
  const J explicitlyDenied = website_inspector::inspectWebsite(
      {{"url", "http://127.0.0.1"}}, loopbackDenylist);
  assert(explicitlyDenied["category"] == "Highly Risky");
  assert(explicitlyDenied["score"] >= 90);
  assert(explicitlyDenied["observed_score"] >= 90);
  assert(explicitlyDenied["scoring"]["observed_scope"] == "strict_denylist");
  const J lookalike = website_inspector::inspectWebsite(
      {{"url", "https://www.youtube.fb/"}});
  assert(lookalike["score"].is_null());
  assert(lookalike["observed_score"] >= 51);
  bool lookalikeFinding = false;
  for (const auto &item : lookalike["findings"])
    lookalikeFinding |= item["id"] == "brand_name_in_unrelated_domain";
  assert(lookalikeFinding);
  const J weakLookalike =
      website_inspector::inspectWebsite({{"url", "https://paypa1.test/"}});
  assert(weakLookalike["observed_score"] >= 51);
  const J hyphenatedLookalike = website_inspector::inspectWebsite(
      {{"url", "https://paypa1-secure-login.test/"}});
  assert(hyphenatedLookalike["score"].is_null());
  assert(hyphenatedLookalike["observed_score"] >= 51);
  assert(hyphenatedLookalike["observed_score"] >
         weakLookalike["observed_score"]);
  bool typoBrandFinding = false, loginHostFinding = false;
  for (const auto &item : hyphenatedLookalike["findings"]) {
    typoBrandFinding |= item["id"] == "brand_lookalike_domain";
    loginHostFinding |= item["id"] == "brand_account_path";
    if (item["id"] == "brand_lookalike_domain")
      assert(item["severity"] == "high");
  }
  assert(typoBrandFinding);
  assert(loginHostFinding);

  const auto finding = [](const S &id, const S &category, const S &family,
                          int points, int reliability = 100) {
    return website_inspector::Finding{id,
                                      category,
                                      family,
                                      "moderate",
                                      id,
                                      "test evidence",
                                      points,
                                      reliability};
  };
  for (const S &host :
       Args{"example.com", "example.in", "example.org",
            "example.in.malicious.net", "example.co.uk"}) {
    const auto tld = website_inspector::assessTld(host);
    assert(tld.approved);
    assert(tld.riskPoints == 0);
    assert(website_inspector::scoreFindings({}).score == 0);
  }
  const auto unapprovedTld = website_inspector::assessTld("example.xyz");
  assert(!unapprovedTld.approved);
  assert(unapprovedTld.suffix == ".xyz");
  assert(unapprovedTld.riskPoints == 51);
  assert(!website_inspector::isStrictlyDeniedHost(
      "example.xyz", website_inspector::config::StrictlyDeniedDomains));
  assert(website_inspector::scoreFindings(
             {finding("unapproved-tld", "tld", "approved_tld_policy",
                      unapprovedTld.riskPoints)})
             .score == 51);
  const std::set<S> testDenylist = {"blocked.example"};
  assert(website_inspector::isStrictlyDeniedHost("blocked.example",
                                                 testDenylist));
  assert(website_inspector::isStrictlyDeniedHost("sub.BLOCKED.example.",
                                                 testDenylist));
  assert(!website_inspector::isStrictlyDeniedHost("blocked.example.evil",
                                                  testDenylist));
  const auto strictDenyScore = website_inspector::scoreFindings(
      {finding("strict-deny", "denylist", "strict_domain_denylist", 90)});
  assert(strictDenyScore.score == 90);
  const auto fakeCom = website_inspector::assessTld("example.com.fake");
  assert(!fakeCom.approved);
  assert(fakeCom.suffix == ".fake");
  assert(fakeCom.riskPoints >= 51);
  const auto nestedNet =
      website_inspector::assessTld("example.in.malicious.net");
  assert(nestedNet.suffix == ".net");
  const auto coUk = website_inspector::assessTld("example.co.uk");
  assert(coUk.suffix == ".uk");
  assert(coUk.approved);
  assert(website_inspector::parseUrl(
      "http://example.com:8080/path?next=example.xyz", parsed, error));
  assert(website_inspector::assessTld(parsed.host).suffix == ".com");

  const std::vector<website_inspector::Finding> findings = {
      finding("same-url-signal", "url", "host", 20),
      finding("same-url-signal", "url", "host", 30),
      finding("url-two", "url", "host", 20),
      finding("content-one", "content", "page-identity", 30),
      finding("content-two", "content", "page-identity", 20),
      finding("observation", "content", "page-identity", 0)};
  const auto scored = website_inspector::scoreFindings(findings);
  assert(scored.score == 60);
  assert(scored.categoryPoints.at("url") == 26);
  assert(scored.categoryPoints.at("content") == 30);
  assert(scored.independentCategories == 2);
  assert(scored.corroborationBonus == 4);
  assert(website_inspector::scoreFindings({}).score == 0);

  const auto reliabilityScore = website_inspector::scoreFindings(
      {finding("weak", "identity", "brand", 20, 50)});
  assert(reliabilityScore.score == 10);
  assert(reliabilityScore.corroborationBonus == 0);
  const auto unresolvedDnsScore = website_inspector::scoreFindings(
      {finding("dns-unresolved", "dns", "hostname-resolution", 8, 90)});
  assert(unresolvedDnsScore.score == 7);
  const auto correlatedScore = website_inspector::scoreFindings(
      {finding("one", "forms", "form-destination", 20),
       finding("two", "forms", "form-destination", 20)});
  assert(correlatedScore.score == 25);
  const auto independentScore = website_inspector::scoreFindings(
      {finding("one", "forms", "form-destination", 12),
       finding("two", "links", "link-destination", 12)});
  assert(independentScore.score == 28);
  assert(independentScore.corroborationBonus == 4);
  const auto cappedScore = website_inspector::scoreFindings(
      {finding("url", "url", "url", 26),
       finding("identity", "identity", "brand", 32),
       finding("content", "content", "content", 30),
       finding("forms", "forms", "form", 40),
       finding("links", "links", "links", 20),
       finding("redirect", "redirect", "redirect", 22),
       finding("tls", "tls", "tls", 12),
       finding("http", "http", "http", 10),
       finding("dns", "dns", "dns", 8)});
  assert(cappedScore.categorySubtotal == 200);
  assert(cappedScore.corroborationBonus == 12);
  assert(cappedScore.score == 100);

  const S html =
      "<html><head><title>Sign in at bank.example</title>"
      "<meta name=\"description\" content=\"Account sign in\"></head>"
      "<body><form action=\"https://collector.example/post\">"
      "<input type=\"password\"></form><p>Verify your account</p>"
      "<script>verify your account suspended account</script></body></html>";
  const J inspected =
      website_inspector::inspectHtml(html, "https://shop.example/");
  assert(inspected.value("title", S()) == "Sign in at bank.example");
  assert(inspected.value("forms", 0) == 1);
  assert(inspected.value("password_forms", 0) == 1);
  assert(inspected.value("external_forms", 0) == 1);
  assert(inspected["metadata"].size() == 1);
  assert(inspected["findings"].size() >= 2);
  assert(inspected["findings"][0]["id"] == "external_password_form");
  assert(inspected["findings"][0]["category"] == "forms");
  assert(inspected["findings"][0]["reliability"] == 90);

  const J siblingDomainForm = website_inspector::inspectHtml(
      "<form action=\"https://collector.shop.example.org/post\">"
      "<input type=\"password\"></form>",
      "https://shop.example.org/login");
  assert(siblingDomainForm.value("external_forms", 0) == 0);
  assert(siblingDomainForm["findings"].empty());

  const J normalLogin = website_inspector::inspectHtml(
      "<form action=\"/session\"><input type=\"password\"></form>",
      "https://example.org/login");
  assert(normalLogin["findings"].empty());
  assert(normalLogin.value("password_forms", 0) == 1);

  const auto scoreHtmlFindings = [](const J &inspection) {
    std::vector<website_inspector::Finding> findings;
    for (const auto &item : inspection["findings"])
      findings.push_back(
          {item.value("id", S()), item.value("module", S()),
           item.value("family", S()), item.value("severity", S()),
           item.value("text", S()), item.value("evidence", S()),
           item.value("points", 0), item.value("reliability", 80)});
    return website_inspector::scoreFindings(findings);
  };
  const J externalLogin = website_inspector::inspectHtml(
      "<p>Verify your account.</p>"
      "<form action=\"https://collector.example/login\">"
      "<input type=\"password\"></form>",
      "https://shop.example/login");
  assert(scoreHtmlFindings(externalLogin).score == 41);
  const J urgentExternalLogin = website_inspector::inspectHtml(
      "<p>Verify your account immediately, within 24 hours.</p>"
      "<form action=\"https://collector.example/login\">"
      "<input type=\"password\"></form>",
      "https://shop.example/login");
  assert(scoreHtmlFindings(urgentExternalLogin).score == 54);

  const J linkAndRedirect = website_inspector::inspectHtml(
      "<a href=\"https://attacker.example/path\">"
      "Visit https://accounts.example.org/login</a>"
      "<img src=\"https://cdn.example.net/image.png\">"
      "<meta http-equiv=\"refresh\" content=\"0;url=https://other.example/\">",
      "https://example.org/");
  assert(linkAndRedirect.value("external_links", 0) == 1);
  assert(linkAndRedirect.value("external_resources", 0) == 1);
  assert(linkAndRedirect.value("meta_refresh", S()) == "other.example");
  bool mismatchedLink = false, crossDomainRefresh = false;
  for (const auto &item : linkAndRedirect["findings"]) {
    mismatchedLink |= item["id"] == "mismatched_link_label";
    crossDomainRefresh |= item["id"] == "cross_domain_meta_refresh";
  }
  assert(mismatchedLink);
  assert(crossDomainRefresh);

  const J pressureForm = website_inspector::inspectHtml(
      "<p>Act now: payment information expires today.</p>"
      "<form action=\"/pay\"><input name=\"card_number\">"
      "<input name=\"cvv\"><input name=\"bank_account\"></form>",
      "https://shop.example.org/checkout");
  assert(pressureForm.value("sensitive_forms", 0) == 1);
  assert(pressureForm["findings"].size() == 1);
  assert(pressureForm["findings"][0]["id"] ==
         "urgent_sensitive_data_request");
}
