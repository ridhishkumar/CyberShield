#pragma once
#include <functional>
#include <string>
namespace scanner {
struct Progress {
  unsigned long long checked = 0, detected = 0, errors = 0;
};
bool available();
bool file(const std::string &bytes);
void device(const std::function<void(Progress)> &update);
} // namespace scanner
