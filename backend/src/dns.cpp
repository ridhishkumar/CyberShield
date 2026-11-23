#include "integrations.h"
#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <future>

// Resolve through the user's OS. No HTTP request or connection to the
// submitted host is made. A slow resolver cannot stall the report indefinitely.
void checkDns(J &report) {
  using namespace std::chrono_literals;
  const S host = report.at("hostname");
  asio::error_code ec;
  asio::ip::make_address(host, ec);
  if (!ec || host.find('.') == S::npos) {
    report["dns_status"] = "skipped";
    report["dns"] =
        "DNS lookup skipped for this local name or numeric address.";
    return;
  }
  static asio::thread_pool pool(2);
  static std::atomic<unsigned> pending{0};
  if (pending.fetch_add(1) >= 2) {
    --pending;
    report["dns_status"] = "busy";
    report["dns"] =
        "DNS lookup busy. Try again to check hostname availability.";
    return;
  }
  auto answer = std::make_shared<std::promise<S>>();
  auto result = answer->get_future();
  try {
    asio::post(pool, [host, answer] {
      S state = "unavailable";
      try {
        asio::io_context context;
        asio::ip::tcp::resolver resolver(context);
        asio::error_code error;
        const auto records = resolver.resolve(host + ".", "443", error);
        if (!error && !records.empty())
          state = "resolved";
        else if (error == asio::error::host_not_found ||
                 error == asio::error::no_data)
          state = "missing";
      } catch (const std::exception &) {
      }
      --pending;
      answer->set_value(std::move(state));
    });
  } catch (...) {
    --pending;
    throw;
  }
  const S state = result.wait_for(1500ms) == std::future_status::ready
                      ? result.get()
                      : "unavailable";
  report["dns_status"] = state;
  if (state == "resolved")
    report["dns"] = "Your DNS resolver found an address for this hostname. "
                    "Site ownership and page availability are unverified.";
  else if (state == "missing") {
    report["dns"] = "Your DNS resolver found no address for this hostname. "
                    "Check the spelling before continuing.";

  } else
    report["dns"] = "DNS lookup was unavailable or timed out. Hostname "
                    "availability is unknown.";
}
