#include "file_verdict.h"
#ifdef _WIN32
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <objbase.h>
#include <windows.h>
#include <wrl/client.h>

namespace {
// The public IAmsiStream and IAntimalware COM interfaces from the Windows
// 10 SDK (amsi.h). Some supported MinGW SDKs omit this header.
constexpr GUID streamId = {0x3e47f2e5,
                           0x81d4,
                           0x4d3b,
                           {0x89, 0x7f, 0x54, 0x50, 0x96, 0x77, 0x03, 0x73}};
constexpr GUID antimalwareId = {
    0x82d29c2e,
    0xf062,
    0x44e6,
    {0xb5, 0xc9, 0x3d, 0x9a, 0x2f, 0x24, 0xa2, 0xdf}};
constexpr GUID antimalwareClass = {
    0xfdb00e52,
    0xa214,
    0x4aa1,
    {0x8f, 0xba, 0x43, 0x57, 0xbb, 0x00, 0x72, 0xec}};
struct AmsiStream : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE GetAttribute(LONG attribute, ULONG size,
                                                 BYTE *out, ULONG *actual) = 0;
  virtual HRESULT STDMETHODCALLTYPE Read(ULONGLONG offset, ULONG size,
                                         BYTE *out, ULONG *actual) = 0;
};
struct Antimalware : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE Scan(AmsiStream *stream, LONG *result,
                                         IUnknown **provider) = 0;
  virtual void STDMETHODCALLTYPE CloseSession(ULONGLONG session) = 0;
};

class SelectedBytes final : public AmsiStream {
  std::atomic<ULONG> references{1};
  const S data;
  const wchar_t *name;

public:
  SelectedBytes(const S &bytes, const wchar_t *sampleName)
      : data(bytes), name(sampleName) {}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override {
    if (!object)
      return E_POINTER;
    *object = nullptr;
    if (!IsEqualIID(iid, IID_IUnknown) && !IsEqualIID(iid, streamId))
      return E_NOINTERFACE;
    *object = static_cast<AmsiStream *>(this);
    AddRef();
    return S_OK;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
  ULONG STDMETHODCALLTYPE Release() override {
    const ULONG left = --references;
    if (!left)
      delete this;
    return left;
  }
  HRESULT STDMETHODCALLTYPE GetAttribute(LONG attribute, ULONG size, BYTE *out,
                                         ULONG *actual) override {
    if (!actual || (!out && size))
      return E_INVALIDARG;
    *actual = 0;
    const ULONGLONG length = data.size(), session = 0;
    const void *address = data.data();
    const void *value;
    switch (attribute) {
    case 0:
      value = L"CyberShield";
      *actual = sizeof(L"CyberShield");
      break; // app name
    case 1:
      value = name;
      *actual = static_cast<ULONG>((wcslen(name) + 1) * sizeof(wchar_t));
      break;
    case 2:
      value = &length;
      *actual = sizeof(length);
      break;
    case 3:
      value = &address;
      *actual = sizeof(address);
      break;
    case 4:
      value = &session;
      *actual = sizeof(session);
      break;
    default:
      return E_NOTIMPL;
    }
    if (size < *actual)
      return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    std::memcpy(out, value, *actual);
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE Read(ULONGLONG offset, ULONG size, BYTE *out,
                                 ULONG *actual) override {
    if (!actual || (!out && size))
      return E_INVALIDARG;
    *actual = offset < data.size() ? static_cast<ULONG>(std::min<ULONGLONG>(
                                         size, data.size() - offset))
                                   : 0;
    if (*actual)
      std::memcpy(out, data.data() + offset, *actual);
    return S_OK;
  }
};
struct Apartment {
  HRESULT status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  ~Apartment() {
    if (SUCCEEDED(status))
      CoUninitialize();
  }
};
} // namespace
#endif

std::optional<Verdict> windowsVerdict(const S &bytes, const wchar_t *name) {
#ifdef _WIN32
  Apartment apartment;
  if (FAILED(apartment.status) && apartment.status != RPC_E_CHANGED_MODE)
    return {};
  using Microsoft::WRL::ComPtr;
  ComPtr<Antimalware> engine;
  if (FAILED(CoCreateInstance(
          antimalwareClass, nullptr, CLSCTX_INPROC_SERVER, antimalwareId,
          reinterpret_cast<void **>(engine.GetAddressOf()))) ||
      !engine)
    return {};
  ComPtr<AmsiStream> stream;
  stream.Attach(new SelectedBytes(bytes, name));
  ComPtr<IUnknown> provider;
  LONG result = -1;
  // A successful call with no answering provider does not cover these bytes.
  if (engine->Scan(stream.Get(), &result, provider.GetAddressOf()) != S_OK ||
      !provider)
    return {};
  if (result == 0 || result == 1)
    return Verdict::noDetection;
  if (result >= 0x8000)
    return Verdict::detected;
  if (result >= 0x4000 && result <= 0x4fff)
    return Verdict::policyBlocked;
#endif
  return {};
}
