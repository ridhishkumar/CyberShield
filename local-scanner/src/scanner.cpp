#include "scanner.h"
#include <asio.hpp>
#include <filesystem>
#include <fstream>
#ifdef _WIN32
#include <windows.h>
#endif
namespace scanner {
using TCP = asio::ip::tcp;
static std::string request(const std::string &command,
                           const std::string *data = nullptr) {
  TCP::iostream stream;
  const auto timeout =
      !data ? 2 : data->size() > 8 * 1024 * 1024 ? 240 : 30;
  stream.expires_after(std::chrono::seconds(timeout));
  stream.connect("127.0.0.1", "3310");
  if (!stream)
    throw std::runtime_error("Local ClamAV daemon unavailable.");
  stream.write(command.data(), command.size());
  stream.put(0);
  if (data) {
    size_t offset = 0;
    while (offset < data->size()) {
      size_t n = std::min<size_t>(65536, data->size() - offset);
      unsigned char size[4] = {0, (unsigned char)(n >> 16),
                               (unsigned char)(n >> 8), (unsigned char)n};
      stream.write((char *)size, 4);
      stream.write(data->data() + offset, n);
      offset += n;
    }
    stream.write("\0\0\0\0", 4);
  }
  stream.flush();
  std::string answer;
  std::getline(stream, answer, '\0');
  if (answer.empty())
    throw std::runtime_error("Engine did not return a verdict.");
  return answer;
}
bool available() {
  try {
    return request("zPING") == "PONG";
  } catch (...) {
    return false;
  }
}
bool file(const std::string &data) {
  auto r = request("zINSTREAM", &data);
  if (r == "stream: OK")
    return false;
  if (r.size() > 6 && r.substr(r.size() - 6) == " FOUND")
    return true;
  if (r.find("INSTREAM size limit exceeded") != std::string::npos ||
      r.find("Size limit exceeded") != std::string::npos)
    throw std::runtime_error(
        "ClamAV rejected the file because its stream or scan-size limit is "
        "below this file's size. Configure StreamMaxLength, MaxFileSize, and "
        "MaxScanSize to at least 200 MB.");
  throw std::runtime_error("ClamAV could not complete this file scan: " + r);
}
void device(const std::function<void(Progress)> &update) {
#ifdef _WIN32
  if (!available())
    throw std::runtime_error("Start the local ClamAV daemon.");
  Progress p;
  bool drive = false;
  for (char c = 'A'; c <= 'Z'; ++c) {
    std::string path = std::string(1, c) + ":\\";
    if (GetDriveTypeA(path.c_str()) != DRIVE_FIXED)
      continue;
    drive = true;
    std::error_code ec;
    std::filesystem::recursive_directory_iterator it(path, ec), end;
    if (ec)
      ++p.errors;
    while (it != end) {
      try {
        auto entry = it->path();
        auto attr = GetFileAttributesW(entry.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES ||
            (attr & FILE_ATTRIBUTE_REPARSE_POINT)) {
          it.disable_recursion_pending();
          ++p.errors;
        } else if (it->is_regular_file()) {
          auto n = it->file_size();
          if (n > 8 * 1024 * 1024) {
            ++p.errors;
          } else {
            std::ifstream in(entry, std::ios::binary);
            std::string data(static_cast<size_t>(n), '\0');
            if (!in.read(data.data(), data.size()) || in.peek() != EOF)
              ++p.errors;
            else {
              if (file(data))
                ++p.detected;
              ++p.checked;
            }
          }
        }
      } catch (const std::exception &) {
        ++p.errors;
        if (!available())
          throw std::runtime_error("Engine disconnected.");
      }
      it.increment(ec);
      if (ec) {
        ++p.errors;
        ec.clear();
      }
      update(p);
    }
  }
  if (!drive)
    throw std::runtime_error("No fixed drive available.");
#else
  throw std::runtime_error(
      "Full-device scanning requires a local Windows installation.");
#endif
}
} // namespace scanner
