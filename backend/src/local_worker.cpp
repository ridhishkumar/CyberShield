#include "scanner.h"
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string>
#ifdef _WIN32
#include <windows.h>
namespace {
std::filesystem::path workerPath() {
  std::wstring path(32768, L'\0');
  DWORD n = GetModuleFileNameW(nullptr, path.data(), DWORD(path.size()));
  if (!n || n >= path.size())
    return {};
  path.resize(n);
  return std::filesystem::path(path).parent_path() / L"cybershield-scanner.exe";
}
struct Handle {
  HANDLE value = nullptr;
  ~Handle() { close(); }
  void close() {
    if (value) {
      CloseHandle(value);
      value = nullptr;
    }
  }
};
} // namespace
#endif
bool workerInstalled() {
#ifdef _WIN32
  return std::filesystem::is_regular_file(workerPath());
#else
  return false;
#endif
}
void runLocalWorker(const std::function<void(scanner::Progress)> &update) {
#ifdef _WIN32
  auto exe = workerPath();
  if (!workerInstalled())
    throw std::runtime_error("Install the scanner beside the server.");
  SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
  Handle read, write;
  if (!CreatePipe(&read.value, &write.value, &security, 0) ||
      !SetHandleInformation(read.value, HANDLE_FLAG_INHERIT, 0))
    throw std::runtime_error("Scanner communication unavailable.");
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = write.value;
  si.hStdError = write.value;
  PROCESS_INFORMATION pi{};
  std::wstring cmd = L"\"" + exe.wstring() + L"\" --consented-web-scan";
  if (!CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, TRUE,
                      CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    throw std::runtime_error("Scanner launch failed.");
  Handle process{pi.hProcess}, thread{pi.hThread};
  write.close();
  char buf[1024];
  DWORD got;
  std::string pending;
  while (ReadFile(read.value, buf, sizeof(buf), &got, nullptr) && got) {
    pending.append(buf, got);
    auto newline = pending.find('\n');
    while (newline != std::string::npos) {
      std::istringstream row(pending.substr(0, newline));
      scanner::Progress p;
      if (row >> p.checked >> p.detected >> p.errors)
        update(p);
      pending.erase(0, newline + 1);
      newline = pending.find('\n');
    }
  }
  WaitForSingleObject(process.value, INFINITE);
  DWORD status;
  if (!GetExitCodeProcess(process.value, &status) || status != 0)
    throw std::runtime_error("Scanner could not finish.");
#else
  (void)update;
  throw std::runtime_error("Windows local worker required.");
#endif
}
