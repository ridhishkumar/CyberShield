#include "scanner.h"
#include <iostream>
int main(int argc, char **argv) {
  if (argc == 2 && std::string(argv[1]) == "--consented-web-scan") {
    try {
      scanner::Progress last;
      scanner::device([&](auto p) {
        last = p;
        if ((p.checked + p.errors) % 25 == 0)
          std::cout << p.checked << " " << p.detected << " " << p.errors
                    << std::endl;
      });
      std::cout << last.checked << " " << last.detected << " " << last.errors
                << std::endl;
      return 0;
    } catch (...) {
      return 1;
    }
  }
  std::cout << "Scan accessible files on all fixed Windows drives with local "
               "ClamAV? Type SCAN: ";
  std::string answer;
  std::getline(std::cin, answer);
  if (answer != "SCAN")
    return 0;
  try {
    scanner::Progress last;
    scanner::device([&](auto p) {
      last = p;
      if (p.checked % 100 == 0)
        std::cout << "\rFiles checked: " << p.checked << std::flush;
    });
    std::cout << "\nChecked " << last.checked << ", detections "
              << last.detected << ", skipped/errors " << last.errors << "\n";
  } catch (const std::exception &e) {
    std::cerr << e.what();
    return 1;
  }
}
