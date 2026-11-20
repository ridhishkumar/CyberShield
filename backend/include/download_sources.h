#pragma once
#include "app.h"

// Explicit host and path pairs keep lookalike domains and unrelated store
// listings from inheriting a publisher match. Paths are case sensitive.
struct DownloadSource {
  S host, path;
};
struct Product {
  S label;
  Args names, publishers;
  std::vector<DownloadSource> sources;
};
inline const std::vector<Product> &downloadCatalogue() {
  static const std::vector<Product> products = {
      {"VLC media player",
       {"vlc", "vlc media player"},
       {"videolan"},
       {{"www.videolan.org", "/vlc"},
        {"videolan.org", "/vlc"},
        {"get.videolan.org", "/vlc"}}},
      {"7-Zip",
       {"7 zip", "7zip"},
       {"igor pavlov"},
       {{"www.7-zip.org", "/"}, {"7-zip.org", "/"}}},
      {"Google Chrome",
       {"google chrome", "chrome"},
       {"google", "google llc"},
       {{"www.google.com", "/chrome"}, {"google.com", "/chrome"}}},
      {"Mozilla Firefox",
       {"firefox", "mozilla firefox"},
       {"mozilla", "mozilla corporation"},
       {{"www.firefox.com", "/"},
        {"firefox.com", "/"},
        {"www.mozilla.org", "/firefox"},
        {"www.mozilla.org", "/en-US/firefox"}}},
      {"Visual Studio Code",
       {"visual studio code", "vscode", "vs code"},
       {"microsoft", "microsoft corporation"},
       {{"code.visualstudio.com", "/"}, {"update.code.visualstudio.com", "/"}}},
      {"Microsoft Edge",
       {"microsoft edge", "edge"},
       {"microsoft", "microsoft corporation"},
       {{"www.microsoft.com", "/edge"}, {"www.microsoft.com", "/en-us/edge"}}},
      {"OBS Studio",
       {"obs", "obs studio"},
       {"obs project", "obs studio contributors"},
       {{"obsproject.com", "/download"},
        {"github.com", "/obsproject/obs-studio"}}},
      {"Blender",
       {"blender"},
       {"blender foundation"},
       {{"www.blender.org", "/download"},
        {"download.blender.org", "/release"}}},
      {"GIMP",
       {"gimp"},
       {"the gimp team", "gimp"},
       {{"www.gimp.org", "/downloads"}, {"download.gimp.org", "/gimp"}}},
      {"Audacity",
       {"audacity"},
       {"audacity", "audacity team", "muse group"},
       {{"www.audacityteam.org", "/download"},
        {"github.com", "/audacity/audacity"}}},
      {"Steam",
       {"steam", "steam client"},
       {"valve", "valve corporation"},
       {{"store.steampowered.com", "/about"},
        {"cdn.akamai.steamstatic.com", "/client/installer"}}},
      {"Python",
       {"python", "python 3"},
       {"python software foundation"},
       {{"www.python.org", "/downloads"}, {"www.python.org", "/ftp/python"}}},
      {"Git for Windows",
       {"git", "git for windows"},
       {"git for windows", "git for windows project"},
       {{"git-scm.com", "/install/windows"},
        {"git-scm.com", "/download"},
        {"git-scm.com", "/downloads"},
        {"gitforwindows.org", "/"},
        {"github.com", "/git-for-windows/git"}}},
      {"LibreOffice",
       {"libreoffice", "libre office"},
       {"the document foundation"},
       {{"www.libreoffice.org", "/download"},
        {"download.documentfoundation.org", "/libreoffice"}}}};
  return products;
}
