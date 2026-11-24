#include "file_verdict.h"

#ifdef _WIN32
#include <atomic>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <system_error>
#include <windows.h>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>

namespace {
class TemporaryExecutable {
  std::filesystem::path path;

public:
  explicit TemporaryExecutable(const S &bytes) {
    static std::atomic<unsigned long long> sequence{0};
    path = std::filesystem::temp_directory_path() /
           (L"CyberShield-signature-" +
            std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(++sequence) + L".exe");
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output)
      throw std::runtime_error("Could not create a temporary signature-check file.");
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.close();
    if (!output) {
      std::error_code error;
      std::filesystem::remove(path, error);
      throw std::runtime_error("Could not write the temporary signature-check file.");
    }
  }

  ~TemporaryExecutable() {
    std::error_code error;
    std::filesystem::remove(path, error);
  }

  const std::filesystem::path &get() const { return path; }
};

static S utf8(const wchar_t *text) {
  if (!text || !*text)
    return {};
  const int bytes =
      WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
  if (bytes <= 1)
    return {};
  S result(static_cast<size_t>(bytes), '\0');
  if (!WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), bytes, nullptr,
                           nullptr))
    return {};
  result.pop_back();
  return result;
}

static S signerName(HANDLE state) {
  if (!state)
    return {};
  CRYPT_PROVIDER_DATA *provider = WTHelperProvDataFromStateData(state);
  if (!provider)
    return {};
  CRYPT_PROVIDER_SGNR *signer =
      WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
  if (!signer)
    return {};
  CRYPT_PROVIDER_CERT *certificate =
      WTHelperGetProvCertFromChain(signer, 0);
  if (!certificate || !certificate->pCert)
    return {};
  const DWORD chars = CertGetNameStringW(
      certificate->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
  if (chars <= 1)
    return {};
  std::wstring name(chars, L'\0');
  if (CertGetNameStringW(certificate->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                         nullptr, name.data(), chars) <= 1)
    return {};
  name.resize(wcslen(name.c_str()));
  return utf8(name.c_str());
}
} // namespace
#endif

J authenticodeAssessment(const S &bytes) {
#ifdef _WIN32
  try {
    TemporaryExecutable temporary(bytes);
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = temporary.get().c_str();

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG result = WinVerifyTrust(nullptr, &action, &data);
    const S signer = signerName(data.hWVTStateData);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);

    if (result == ERROR_SUCCESS)
      return {{"status", "valid"},
              {"signer", signer},
              {"message", "The embedded signature passed local Windows trust verification."}};
    if (result == TRUST_E_NOSIGNATURE ||
        result == TRUST_E_SUBJECT_FORM_UNKNOWN ||
        result == TRUST_E_PROVIDER_UNKNOWN)
      return {{"status", "unsigned"},
              {"signer", signer},
              {"message", "No embedded Authenticode signature was found."}};
    if (result == TRUST_E_BAD_DIGEST)
      return {{"status", "invalid_signature"},
              {"signer", signer},
              {"message", "The embedded signature digest does not match the file."}};
    if (result == CERT_E_REVOKED)
      return {{"status", "revoked"},
              {"signer", signer},
              {"message", "Windows reports that the signing certificate is revoked."}};
    if (result == TRUST_E_EXPLICIT_DISTRUST)
      return {{"status", "distrusted"},
              {"signer", signer},
              {"message", "Windows explicitly distrusts the signing certificate."}};
    if (result == TRUST_E_SUBJECT_NOT_TRUSTED ||
        result == CERT_E_UNTRUSTEDROOT || result == CERT_E_CHAINING)
      return {{"status", "present_untrusted"},
              {"signer", signer},
              {"message", "A signature is present, but its signer is not trusted by the cached local trust data."}};
    return {{"status", "verification_unavailable"},
            {"signer", signer},
            {"message", "Windows could not complete local signature verification."}};
  } catch (const std::filesystem::filesystem_error &error) {
    return {{"status", "verification_unavailable"},
            {"signer", ""},
            {"message", S("Local signature check could not access a temporary file: ") +
                            error.what()}};
  } catch (const std::runtime_error &error) {
    return {{"status", "verification_unavailable"},
            {"signer", ""},
            {"message", error.what()}};
  }
#else
  (void)bytes;
  return {{"status", "verification_unavailable"},
          {"signer", ""},
          {"message", "Authenticode verification is available only on Windows."}};
#endif
}
