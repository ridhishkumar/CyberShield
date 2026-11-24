#pragma once
#include "app.h"
#include <memory>
struct Finding {
  S text;
  int points;
};
inline bool linearSearch(const Args &values, const S &key) {
  for (auto &v : values)
    if (v == key)
      return true;
  return false;
}
inline void sortFindings(std::vector<Finding> &rows) {
  for (size_t end = rows.size(); end > 1; --end) {
    bool swapped = false;
    for (size_t j = 1; j < end; ++j)
      if (rows[j].points > rows[j - 1].points) {
        std::swap(rows[j], rows[j - 1]);
        swapped = true;
      }
    if (!swapped)
      break;
  }
}
// A linked FIFO keeps extracted email links in reading order.
class LinkQueue {
  struct Node {
    S url;
    std::unique_ptr<Node> next;
  };
  std::unique_ptr<Node> first;
  Node *last = nullptr;

public:
  void push(const S &url) {
    auto n = std::make_unique<Node>();
    n->url = url;
    auto tail = n.get();
    if (last)
      last->next = std::move(n);
    else
      first = std::move(n);
    last = tail;
  }
  bool empty() const { return !first; }
  S pop() {
    S url = first->url;
    first = std::move(first->next);
    if (!first)
      last = nullptr;
    return url;
  }
};
// Match paired delimiters around links in plain-text messages.
inline S trimLink(S url) {
  std::vector<char> stack;
  size_t i = 0;
  for (; i < url.size(); ++i) {
    char c = url[i];
    if (c == '(' || c == '[' || c == '{')
      stack.push_back(c);
    if (c == ')' || c == ']' || c == '}') {
      const char expected = c == ')' ? '(' : c == ']' ? '[' : '{';
      if (stack.empty() || stack.back() != expected)
        break;
      stack.pop_back();
    }
  }
  url.resize(i);
  while (!url.empty() && S(".,;!?").find(url.back()) != S::npos)
    url.pop_back();
  return url;
}
