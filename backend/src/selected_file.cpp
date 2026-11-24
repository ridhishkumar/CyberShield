#include "file_verdict.h"
#include "scanner.h"
#include "dsa.h"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <optional>
#include <cmath>
struct FileType {
  const char *label;
  const wchar_t *sampleName;
};
static bool hasPeHeader(const S &bytes) {
  if (bytes.size() < 64 || bytes.compare(0, 2, "MZ") != 0)
    return false;
  uint32_t offset = 0;
  for (int i = 0; i < 4; ++i)
    offset |= uint32_t(static_cast<unsigned char>(bytes[60 + i])) << (8 * i);
  return offset >= 64 && offset <= bytes.size() - 4 &&
         bytes.compare(offset, 4, "PE\0\0", 4) == 0;
}
static FileType identify(const S &bytes) {
  if (bytes.rfind("%PDF-", 0) == 0)
    return {"PDF document", L"selected.pdf"};
  if (hasPeHeader(bytes))
    return {"Windows PE executable", L"selected.exe"};
  if (bytes.rfind("MZ", 0) == 0)
    return {"DOS/Windows executable header", L"selected.exe"};
  if (bytes.rfind("PK\003\004", 0) == 0)
    return {"ZIP-based container", L"selected.zip"};
  if (bytes.rfind("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 0) == 0)
    return {"OLE compound container", L"selected.bin"};
  if (bytes.rfind("\x89PNG\r\n\x1a\n", 0) == 0)
    return {"PNG image", L"selected.png"};
  if (bytes.rfind("\xff\xd8\xff", 0) == 0)
    return {"JPEG image", L"selected.jpg"};
  const size_t sampleSize = std::min<size_t>(bytes.size(), 4096);
  size_t printable = 0;
  bool hasNull = false;
  for (size_t i = 0; i < sampleSize; ++i) {
    const unsigned char c = static_cast<unsigned char>(bytes[i]);
    hasNull |= c == 0;
    printable += (c == 9 || c == 10 || c == 13 || c >= 32);
  }
  if (sampleSize && !hasNull && printable * 100 >= sampleSize * 95)
    return {"Plain-text document", L"selected.txt"};
  return {"Unrecognized by the local header check", L"selected.bin"};
}

static double byteEntropy(const S &bytes) {
  if (bytes.empty()) return 0.0;
  uint64_t counts[256] = {};
  for (unsigned char c : bytes) ++counts[c];
  double entropy = 0.0;
  for (uint64_t count : counts) {
    if (!count) continue;
    const double probability = static_cast<double>(count) / bytes.size();
    entropy -= probability * std::log2(probability);
  }
  return entropy;
}
static bool containsAsciiInsensitive(const S &bytes, const S &needle) {
  if (needle.empty())
    return false;
  return std::search(
             bytes.begin(), bytes.end(), needle.begin(), needle.end(),
             [](unsigned char left, unsigned char right) {
               return std::tolower(left) == std::tolower(right);
             }) != bytes.end();
}
J analyzeFile(const S &bytes, const S &extension, const S &fileName) {
  const auto started = std::chrono::steady_clock::now();
  const auto type = identify(bytes);
  S engine = "Local ClamAV daemon";
  S providerNote;
  std::optional<Verdict> verdict;
  try {
    verdict = scanner::file(bytes) ? Verdict::detected : Verdict::noDetection;
  } catch (const std::exception &error) {
    providerNote = error.what();
    verdict = windowsVerdict(bytes, type.sampleName);
    engine = verdict ? "Windows Antimalware Scan Interface (AMSI)"
                     : "Local file inspection";
  }
  S category = "Insufficient information";
  S basis = "File inspection completed. No antivirus verdict was available.";
  S advice = "Before opening the file, scan it in Windows Security or start "
             "ClamAV and retry.";
  if (verdict == Verdict::detected) {
    category = "High risk";
    basis = "The antivirus engine reported a detection.";
    advice = "Leave the file closed and review the detection in your antivirus "
             "tool.";
  } else if (verdict == Verdict::noDetection) {
    category = "Lower risk";
    basis =
        "The antivirus engine completed its check and reported no detection.";
    advice = "Verify the download source before opening the file. A single "
             "scan has limited coverage.";
  } else if (verdict == Verdict::policyBlocked) {
    category = "Suspicious";
    basis = "The Windows antimalware provider blocked this content under its "
            "policy.";
    advice = "Leave the file closed and review your Windows Security or "
             "administrator guidance.";
  }
  const S sha256 = digest(bytes);
  J notes = {S("Header format: ") + type.label,
             "Bytes examined: " + std::to_string(bytes.size()),
             "SHA-256: " + sha256};
  if (!providerNote.empty())
    notes.push_back("ClamAV provider: " + providerNote);
  const bool documentName = extension == "pdf" || extension == "png" ||
                            extension == "jpg" || extension == "jpeg" ||
                            extension == "txt" || extension == "docx";
  const bool documentContainsExecutable =
      documentName && hasPeHeader(bytes);
  if (documentContainsExecutable) {
    notes.push_back("The selected ." + extension +
                    " file contains a Windows executable header.");
    if (category != "High risk") {
      category = "Suspicious";
      basis += " The executable content conflicts with the filename extension.";
      advice = "Leave the file closed and obtain a fresh copy from the "
               "expected publisher.";
    }
  }
  int staticPenalty = 0;
  const bool mismatch =
      (extension == "pdf" && type.label != std::string("PDF document")) ||
      (type.label == std::string("PDF document") && extension != "pdf") ||
      (extension == "png" && type.label != std::string("PNG image")) ||
      (type.label == std::string("PNG image") && extension != "png") ||
      ((extension == "jpg" || extension == "jpeg") &&
       type.label != std::string("JPEG image")) ||
      (type.label == std::string("JPEG image") &&
       extension != "jpg" && extension != "jpeg") ||
      (extension == "zip" && type.label != std::string("ZIP-based container")) ||
      (type.label == std::string("ZIP-based container") && extension != "zip" &&
       extension != "docx" && extension != "xlsx" && extension != "pptx" &&
       extension != "appx" && extension != "msix") ||
      (extension == "exe" && type.label != std::string("Windows PE executable")) ||
      (extension == "msi" &&
       type.label != std::string("OLE compound container")) ||
      (type.label == std::string("Plain-text document") &&
       extension != "txt" && extension != "csv" && extension != "log" &&
       extension != "md" && extension != "json" && extension != "xml" &&
       extension != "html" && extension != "css");
  const bool extensionMismatch = mismatch || documentContainsExecutable;
  J staticIndicators = J::array();
  if (extensionMismatch) {
    staticPenalty += 35;
    notes.push_back("The file contents do not match the selected filename extension or expected header.");
    if (category != "High risk") {
      category = "Suspicious";
      basis += " The file type and filename extension do not agree.";
      advice = "Do not open the file until you confirm its actual format and obtain it from the expected source.";
    }
  }
  if (type.label == std::string("PDF document")) {
    int activeMarkers = 0;
    for (const S &marker : Args{"/OpenAction", "/AA", "/Launch", "/JavaScript", "/EmbeddedFile", "/RichMedia"})
      if (containsAsciiInsensitive(bytes, marker)) ++activeMarkers;
    if (activeMarkers) {
      staticPenalty += std::min(30, activeMarkers * 10);
      notes.push_back("The PDF contains active-content or embedded-object markers; these can be legitimate but deserve review.");
      staticIndicators.push_back(
          {{"id", "pdf_active_content_markers"},
           {"name", "PDF active-content markers"},
           {"family", "active_content"},
           {"strength", std::min(70, 25 + activeMarkers * 10)},
           {"confidence", 78},
           {"explanation",
            "The PDF contains active-content or embedded-object markers; "
            "these can be legitimate but deserve review."},
           {"evidence", std::to_string(activeMarkers) + " marker(s)"},
           {"verification_status", "heuristic"}});
    }
  }
  if (type.label == std::string("ZIP-based container") &&
      (containsAsciiInsensitive(bytes, "vbaproject.bin") ||
       containsAsciiInsensitive(bytes, "word/vba") ||
       containsAsciiInsensitive(bytes, "xl/macrosheets"))) {
    staticPenalty += 20;
    notes.push_back("The archive appears to contain Office macro-related components.");
    staticIndicators.push_back(
        {{"id", "office_macro_components"},
         {"name", "Office macro-related components"},
         {"family", "active_content"},
         {"strength", 62},
         {"confidence", 79},
         {"explanation",
          "The archive appears to contain Office macro-related components."},
         {"evidence", "VBA project or macro-sheet marker"},
         {"verification_status", "heuristic"}});
  }
  if (linearSearch(Args{"ps1", "vbs", "js", "jse", "hta", "bat", "cmd", "scr"}, extension)) {
    int scriptMarkers = 0;
    for (const S &marker : Args{"downloadstring", "frombase64string", "wscript.shell", "invoke-expression", "powershell -enc", "createobject("})
      if (containsAsciiInsensitive(bytes, marker)) ++scriptMarkers;
    if (scriptMarkers) {
      staticPenalty += std::min(30, scriptMarkers * 10);
      notes.push_back("The script contains one or more command-execution, download, or encoded-payload patterns.");
      staticIndicators.push_back(
          {{"id", "script_execution_patterns"},
           {"name", "Script execution or download patterns"},
           {"family", "script_behavior"},
           {"strength", std::min(82, 32 + scriptMarkers * 14)},
           {"confidence", 73},
           {"explanation",
            "The script contains command-execution, download, or "
            "encoded-payload patterns."},
           {"evidence", std::to_string(scriptMarkers) + " pattern(s)"},
           {"verification_status", "heuristic"}});
    }
  }
  if (hasPeHeader(bytes) && byteEntropy(bytes) > 7.2) {
    staticPenalty += 10;
    notes.push_back("The executable has high byte entropy, which can occur in packed or compressed files and is not proof of malware.");
    staticIndicators.push_back(
        {{"id", "high_executable_entropy"},
         {"name", "High executable byte entropy"},
         {"family", "packing_indicator"},
         {"strength", 30},
         {"confidence", 57},
         {"explanation",
          "High byte entropy can occur in packed or compressed files and is "
          "not proof of malware."},
         {"evidence", "Measured entropy exceeds 7.2 bits per byte"},
         {"verification_status", "heuristic"}});
  }
  if (staticPenalty >= 15 && category != "High risk")
    category = "Suspicious";
  int trustScore = -1;
  if (verdict == Verdict::detected) trustScore = 0;
  else if (verdict == Verdict::noDetection) trustScore = std::max(0, 75 - staticPenalty);
  else if (verdict == Verdict::policyBlocked) trustScore = 15;
  else {
    // A static-only score is deliberately conservative when no antivirus engine answered.
    trustScore = (type.label == std::string("Unrecognized by the local header check") ? 35 :
                  type.label == std::string("Windows PE executable") ? 30 :
                  type.label == std::string("Plain-text document") ? 55 : 45) - staticPenalty;
    trustScore = std::max(0, trustScore);
    basis = "No antivirus verdict was available. This is a limited static-only assessment of file format and selected content markers, not a malware scan.";
    advice = "Use Windows Security or an updated antivirus engine for a full malware scan before opening the file.";
  }
  notes.push_back("Static checks include file signature and extension consistency, selected active-content/script markers, SHA-256 and (for PE files) byte entropy. These checks cannot establish that a file is safe.");
  const S scannerStatus =
      verdict == Verdict::detected
          ? "detected"
          : verdict == Verdict::noDetection
                ? "no_detection"
                : verdict == Verdict::policyBlocked ? "policy_blocked"
                                                     : "unavailable";
  const J authenticode =
      hasPeHeader(bytes)
          ? authenticodeAssessment(bytes)
          : J{{"status", "not_applicable"},
              {"signer", ""},
              {"message", "The detected file type is not a Windows PE executable."}};
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started)
                .count();
  notes.push_back("Elapsed milliseconds: " + std::to_string(ms));
  return {{"type", "File"},
          {"target", "Selected file"},
          {"file_name", fileName},
          {"file_size_bytes", bytes.size()},
          {"sha256", sha256},
          {"category", category},
          {"score", trustScore < 0 ? J(nullptr) : J(100 - trustScore)},
          {"trust_score", trustScore < 0 ? J(nullptr) : J(trustScore)},
          {"static_penalty", staticPenalty},
          {"detections",
           verdict ? J(*verdict == Verdict::detected ? 1 : 0) : J(nullptr)},
          {"file_assessment",
           {{"file_name", fileName},
            {"size_bytes", bytes.size()},
            {"sha256", sha256},
            {"file_type", type.label},
            {"extension", extension},
            {"extension_mismatch", extensionMismatch},
            {"static_indicators", staticIndicators},
            {"scanner_status", scannerStatus},
            {"scanner_engine", engine},
            {"authenticode", authenticode}}},
          {"basis", basis},
          {"findings", J::array()},
          {"advice", advice},
          {"source", engine},
          {"notes", notes}};
}
