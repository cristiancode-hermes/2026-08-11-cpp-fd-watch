// SPDX-License-Identifier: MIT
// cpp-fd-watch — Linux file descriptor analyzer (C++23)
// Reads /proc/sys/fs/file-nr, /proc/sys/fs/nr_open and per-process
// /proc/<pid>/{fd,comm,limits,stat} to show system-wide fd usage, the top
// fd consumers, per-process soft/hard limits and limit pressure.
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o fd-watch
// Usage: ./fd-watch [--watch N] [--json] [--top N] [--min N] [--no-color] [--selftest] [--help]

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace fdwatch {

// ── ANSI palette (mutable so --no-color can blank it) ──────────────────────
bool g_color = true;
struct Palette {
  std::string bold, dim, cyan, green, yellow, red, rst;
};
Palette P;

void init_palette() {
  P.bold   = "\x1b[1m";
  P.dim    = "\x1b[2m";
  P.cyan   = "\x1b[38;5;117m";
  P.green  = "\x1b[38;5;158m";
  P.yellow = "\x1b[38;5;222m";
  P.red    = "\x1b[38;5;210m";
  P.rst    = "\x1b[0m";
}
void disable_color() {
  P.bold = P.dim = P.cyan = P.green = P.yellow = P.red = P.rst = "";
}

// ── Small helpers ──────────────────────────────────────────────────────────
std::string read_file(const std::string& path) {
  std::ifstream f(path);
  if (!f) return {};
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

std::string trim(std::string s) {
  auto is_sp = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
  while (!s.empty() && is_sp(s.front())) s.erase(s.begin());
  while (!s.empty() && is_sp(s.back())) s.pop_back();
  return s;
}

// 3488 -> "3.488"; 1048576 -> "1.048.576"
std::string fmt_int(long long n) {
  bool neg = n < 0;
  std::string s = std::to_string(neg ? -n : n);
  std::string out;
  int cnt = 0;
  for (auto it = s.rbegin(); it != s.rend(); ++it) {
    if (cnt && cnt % 3 == 0) out += '.';
    out += *it;
    ++cnt;
  }
  std::reverse(out.begin(), out.end());
  return neg ? "-" + out : out;
}

// 3488 -> "3.49K"; 9223372036854775807 -> "9.22E"
std::string fmt_human(long long n) {
  if (n < 0) return "-" + fmt_human(-n);
  if (n < 10000) return fmt_int(n);
  double v = static_cast<double>(n);
  static const char* units[] = {"K", "M", "G", "T", "P", "E"};
  int u = -1;
  while (v >= 1000.0 && u < 5) { v /= 1000.0; ++u; }
  char buf[32];
  std::snprintf(buf, sizeof buf, "%.2f%s", v, units[u]);
  return buf;
}

std::string json_escape(const std::string& s) {
  std::string out;
  for (unsigned char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char b[8];
          std::snprintf(b, sizeof b, "\\u%04x", c);
          out += b;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

// ── /proc parsing ──────────────────────────────────────────────────────────
struct FileNr {
  long long allocated = 0;
  long long unused = 0;
  long long max = 0;
  bool ok = false;
};

FileNr parse_file_nr(const std::string& content) {
  FileNr r;
  std::istringstream ss(content);
  if (ss >> r.allocated >> r.unused >> r.max) r.ok = true;
  return r;
}

long long parse_single_number(const std::string& content) {
  std::string t = trim(content);
  long long v = 0;
  auto [ptr, ec] = std::from_chars(t.data(), t.data() + t.size(), v);
  if (ec == std::errc{} && ptr == t.data() + t.size()) return v;
  return -1;
}

// Returns {soft, hard}; -1 = unlimited, 0 = line not found
std::pair<long long, long long> parse_max_open_files(const std::string& limits) {
  auto to_ll = [](const std::string& s) -> long long {
    if (s == "unlimited") return -1;
    long long v = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{}) return -1;
    return v;
  };
  std::istringstream ss(limits);
  std::string line;
  while (std::getline(ss, line)) {
    if (!line.starts_with("Max open files")) continue;
    // name spans 3 tokens ("Max open files") — parse the rest after the prefix
    std::string rest = line.substr(std::string("Max open files").size());
    std::istringstream ls(rest);
    std::string soft_s, hard_s, unit;
    if (ls >> soft_s >> hard_s >> unit)
      return {to_ll(soft_s), to_ll(hard_s)};
  }
  return {0, 0};
}

// /proc/<pid>/stat: "pid (comm) state ..." — comm may contain ')' so use rfind
char parse_state(const std::string& stat) {
  auto close = stat.rfind(')');
  if (close == std::string::npos || close + 2 >= stat.size()) return '?';
  size_t i = close + 1;
  while (i < stat.size() && stat[i] == ' ') ++i;
  return i < stat.size() ? stat[i] : '?';
}

// ── Process scan ───────────────────────────────────────────────────────────
struct ProcFd {
  int pid = 0;
  std::string name;
  long long fds = 0;   // -1 = no access to /proc/<pid>/fd
  long long soft = 0;  // -1 = unlimited
  long long hard = 0;
  char state = '?';
};

struct ScanResult {
  std::vector<ProcFd> procs;
  int no_access = 0;
};

// Count entries in /proc/<pid>/fd without throwing on permission errors
long long count_fd_entries(const std::string& pid_str, bool& ok) {
  std::error_code ec;
  std::filesystem::directory_iterator it{"/proc/" + pid_str + "/fd", ec};
  if (ec) { ok = false; return 0; }
  long long n = 0;
  while (it != std::filesystem::directory_iterator{}) {
    ++n;
    it.increment(ec);
    if (ec) break;
  }
  ok = true;
  return n;
}

ScanResult scan_procs() {
  ScanResult r;
  std::error_code ec;
  std::filesystem::directory_iterator it{"/proc", ec};
  if (ec) return r;
  for (const auto& entry : it) {
    std::string name = entry.path().filename().string();
    if (name.empty() || !std::all_of(name.begin(), name.end(),
                                     [](char c) { return c >= '0' && c <= '9'; }))
      continue;
    int pid = std::stoi(name);
    ProcFd p;
    p.pid = pid;
    bool ok = false;
    p.fds = count_fd_entries(name, ok);
    if (!ok) {
      ++r.no_access;
      p.fds = -1;
    }
    p.name = trim(read_file("/proc/" + name + "/comm"));
    if (p.name.empty()) p.name = "?";
    auto [soft, hard] = parse_max_open_files(read_file("/proc/" + name + "/limits"));
    p.soft = soft;
    p.hard = hard;
    p.state = parse_state(read_file("/proc/" + name + "/stat"));
    r.procs.push_back(std::move(p));
  }
  std::sort(r.procs.begin(), r.procs.end(),
            [](const ProcFd& a, const ProcFd& b) { return a.fds > b.fds; });
  return r;
}

// ── Rendering ──────────────────────────────────────────────────────────────
struct Snapshot {
  FileNr nr;
  long long nr_open = 0;
  ScanResult scan;
  long long total_fds = 0;
  int scanned = 0;
  double util_pct = 0.0;
  double avg_fds = 0.0;
  int pressure = 0;
};

Snapshot take_snapshot() {
  Snapshot s;
  s.nr = parse_file_nr(read_file("/proc/sys/fs/file-nr"));
  s.nr_open = parse_single_number(read_file("/proc/sys/fs/nr_open"));
  s.scan = scan_procs();
  long long sum = 0;
  for (const auto& p : s.scan.procs) {
    if (p.fds >= 0) sum += p.fds;
    if (p.soft > 0 && p.fds >= static_cast<long long>(0.8 * static_cast<double>(p.soft)))
      ++s.pressure;
  }
  s.total_fds = sum;
  s.scanned = static_cast<int>(s.scan.procs.size());
  if (s.scanned > 0) s.avg_fds = static_cast<double>(sum) / s.scanned;
  if (s.nr_open > 0) s.util_pct = 100.0 * static_cast<double>(s.nr.allocated) / s.nr_open;
  return s;
}

std::string bar(long long value, long long max_value, int width) {
  int filled = 0;
  if (max_value > 0)
    filled = static_cast<int>(std::clamp(std::llround(static_cast<double>(value) /
                                                      max_value * width), 0LL, (long long)width));
  return std::string(filled, '|') + std::string(width - filled, '.');
}

// forward decls (defined below)
std::string fmt_pct(double v);
std::string fmt_num(double v);

void print_system_line(const Snapshot& s, bool show_rates, double alloc_rate, double fd_rate) {
  std::cout << P.cyan << "  SYSTEM FDS      " << P.rst
            << "allocated " << P.bold << fmt_int(s.nr.allocated) << P.rst
            << "   unused " << P.bold << fmt_int(s.nr.unused) << P.rst
            << "   file-max " << P.bold << fmt_human(s.nr.max) << P.rst
            << "   nr_open " << P.bold << fmt_human(s.nr_open) << P.rst
            << "   " << P.bold << P.yellow << fmt_pct(s.util_pct) << P.rst << '\n';
  std::cout << P.cyan << "  PROCESSES      " << P.rst
            << P.bold << s.scanned << P.rst << " scanned";
  if (s.scan.no_access > 0)
    std::cout << "  " << P.yellow << s.scan.no_access << P.rst << " without access";
  std::cout << "   total fds " << P.bold << fmt_int(s.total_fds) << P.rst
            << "   avg " << P.bold << fmt_num(s.avg_fds) << P.rst << "/proc";
  if (s.pressure > 0)
    std::cout << "   " << P.red << s.pressure << " near limit" << P.rst;
  std::cout << '\n';
  if (show_rates) {
    std::cout << P.cyan << "  RATES          " << P.rst
              << "fd alloc " << P.bold << (alloc_rate >= 0 ? "+" : "") << fmt_num(alloc_rate) << P.rst << "/s"
              << "   process fds " << P.bold << (fd_rate >= 0 ? "+" : "") << fmt_num(fd_rate) << P.rst << "/s\n";
  }
}

void print_states(const Snapshot& s) {
  if (s.scan.procs.empty()) return;
  int run = 0, sleep = 0, disk = 0, zombie = 0, idle = 0, other = 0;
  for (const auto& p : s.scan.procs) {
    switch (p.state) {
      case 'R': ++run; break;
      case 'S': ++sleep; break;
      case 'D': ++disk; break;
      case 'Z': ++zombie; break;
      case 'I': ++idle; break;
      default: ++other; break;
    }
  }
  std::cout << P.cyan << "  STATES         " << P.rst
            << "running " << P.bold << run << P.rst
            << "   sleeping " << P.bold << sleep << P.rst
            << "   disk " << P.bold << disk << P.rst;
  if (zombie > 0) std::cout << "   " << P.red << "zombie " << zombie << P.rst;
  else std::cout << "   zombie " << P.bold << zombie << P.rst;
  std::cout << "   idle " << P.bold << idle << P.rst
            << "   other " << P.bold << other << P.rst << '\n';
}

// Wrap snprintf-based percent/double formatting (locale-independent, 1 decimal)
std::string fmt_pct(double v) {
  char buf[16];
  std::snprintf(buf, sizeof buf, "%.1f%%", v);
  return buf;
}

// helper to print a double with 1 decimal (for avg_fds / rates)
std::string fmt_num(double v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%.1f", v);
  return buf;
}

void print_table(const Snapshot& s, int top_n, long long min_fds) {
  std::cout << P.bold << "  TOP FD CONSUMERS" << P.rst << "  (min " << fmt_int(min_fds) << " fds, showing " << top_n << ")\n";
  std::cout << P.dim << "   PID     NAME                        FDS     SOFT LIMIT   %LIMIT  ST  BAR" << P.rst << '\n';
  long long max_fds = 0;
  int shown = 0;
  for (const auto& p : s.scan.procs) {
    if (shown >= top_n) break;
    if (p.fds < min_fds) continue;
    if (p.fds > max_fds) max_fds = p.fds;
    ++shown;
  }
  shown = 0;
  for (const auto& p : s.scan.procs) {
    if (shown >= top_n) break;
    if (p.fds < min_fds) continue;
    ++shown;
    char buf[256];
    double pct = (p.soft > 0) ? 100.0 * static_cast<double>(p.fds) / p.soft : 0.0;
    const char* pct_color = (p.soft > 0 && pct >= 80.0) ? P.red.c_str()
                          : (p.soft > 0 && pct >= 50.0) ? P.yellow.c_str()
                          : P.green.c_str();
    std::string fds_s = p.fds < 0 ? "-" : fmt_int(p.fds);
    std::string soft_s = p.soft < 0 ? "unlim" : (p.soft == 0 ? "?" : fmt_int(p.soft));
    // pad manually so ANSI codes in the colored cell don't break column width
    std::string pct_s;
    if (p.soft > 0) {
      std::string plain = fmt_pct(pct);
      int pad = std::max(0, 8 - static_cast<int>(plain.size()));
      pct_s = std::string(pad, ' ') + pct_color + plain + P.rst;
    } else {
      pct_s = "       -";
    }
    std::string bar_s = p.fds < 0 ? std::string(20, '?') : bar(p.fds, max_fds, 20);
    std::snprintf(buf, sizeof buf, "  %6d  %-24s %8s %12s %s   %c   %s",
                  p.pid, p.name.c_str(), fds_s.c_str(), soft_s.c_str(), pct_s.c_str(),
                  p.state, bar_s.c_str());
    std::cout << buf << '\n';
  }
  if (shown == 0) std::cout << P.dim << "  (no processes with fds >= " << fmt_int(min_fds) << ")" << P.rst << '\n';
  std::cout << '\n';
}

std::string build_json(const Snapshot& s) {
  std::ostringstream j;
  j << "{\n";
  j << "  \"system\": {\"allocated\": " << s.nr.allocated
    << ", \"unused\": " << s.nr.unused
    << ", \"file_max\": " << s.nr.max
    << ", \"nr_open\": " << s.nr_open
    << ", \"utilization_pct\": " << std::round(s.util_pct * 100.0) / 100.0 << "},\n";
  j << "  \"processes\": [\n";
  bool first = true;
  for (const auto& p : s.scan.procs) {
    if (!first) j << ",\n";
    first = false;
    double pct = (p.soft > 0) ? 100.0 * static_cast<double>(p.fds) / p.soft : 0.0;
    j << "    {\"pid\": " << p.pid
      << ", \"name\": \"" << json_escape(p.name) << "\""
      << ", \"fds\": " << p.fds
      << ", \"soft\": " << p.soft
      << ", \"hard\": " << p.hard
      << ", \"state\": \"" << p.state << "\""
      << ", \"limit_pct\": " << std::round(pct * 100.0) / 100.0 << "}";
  }
  j << "\n  ],\n";
  j << "  \"summary\": {\"scanned\": " << s.scanned
    << ", \"no_access\": " << s.scan.no_access
    << ", \"total_fds\": " << s.total_fds
    << ", \"avg_fds\": " << std::round(s.avg_fds * 10.0) / 10.0
    << ", \"pressure\": " << s.pressure << "}\n";
  j << "}\n";
  return j.str();
}

void run_watch(int interval, int top_n, long long min_fds) {
  using clock = std::chrono::steady_clock;
  auto prev_time = clock::now();
  Snapshot prev = take_snapshot();
  while (true) {
    Snapshot s = take_snapshot();
    auto now = clock::now();
    double dt = std::chrono::duration<double>(now - prev_time).count();
    if (dt <= 0.0) dt = 0.001;
    double alloc_rate = static_cast<double>(s.nr.allocated - prev.nr.allocated) / dt;
    double fd_rate = static_cast<double>(s.total_fds - prev.total_fds) / dt;
    prev_time = now;
    prev = s;

    std::cout << "\x1b[2J\x1b[H";
    std::cout << P.bold << "  FD WATCH — Linux file descriptor usage  (rates: last " << interval << "s)" << P.rst << '\n';
    std::cout << P.dim << "  ------------------------------------------------------------------------------" << P.rst << '\n';
    print_system_line(s, true, alloc_rate, fd_rate);
    print_states(s);
    std::cout << '\n';
    print_table(s, top_n, min_fds);
    std::cout << P.dim << "  Ctrl+C para salir" << P.rst << '\n';
    std::cout << std::flush;
    std::this_thread::sleep_for(std::chrono::seconds(interval));
  }
}

void print_help(const char* prog) {
  std::cout << "Usage: " << prog << " [options]\n"
            << "Analizador de file descriptors de Linux (C++23).\n\n"
            << "Opciones:\n"
            << "  --watch N     refresco en vivo cada N segundos (tasas delta)\n"
            << "  --json        salida JSON completa para scripting\n"
            << "  --top N       top N procesos con mas fds (default 10)\n"
            << "  --min N       solo procesos con fds >= N\n"
            << "  --no-color    sin colores ANSI (pipes/logs)\n"
            << "  --selftest    auto-verificacion\n"
            << "  -h, --help    esta ayuda\n\n"
            << "Fuentes: /proc/sys/fs/file-nr, /proc/sys/fs/nr_open, /proc/<pid>/{fd,comm,limits,stat}\n";
}

// ── Selftest ───────────────────────────────────────────────────────────────
int g_pass = 0, g_fail = 0;
void t_check(const char* name, bool cond) {
  if (cond) { ++g_pass; std::cout << "  PASS  " << name << '\n'; }
  else { ++g_fail; std::cout << "  FAIL  " << name << '\n'; }
}

int run_selftest() {
  // 1. file-nr parsing (tab separated)
  auto fn = parse_file_nr("3488\t0\t9223372036854775807\n");
  t_check("file-nr tab parse", fn.ok && fn.allocated == 3488 && fn.unused == 0 && fn.max == 9223372036854775807LL);
  // 2. file-nr with spaces
  fn = parse_file_nr("  100 5 1024 ");
  t_check("file-nr spaces parse", fn.ok && fn.allocated == 100 && fn.unused == 5 && fn.max == 1024);
  // 3. file-nr garbage -> not ok
  fn = parse_file_nr("abc def");
  t_check("file-nr garbage rejected", !fn.ok);
  // 4. nr_open single number
  t_check("nr_open parse", parse_single_number("1048576\n") == 1048576);
  // 5. max open files numeric
  auto lim = parse_max_open_files("Limit                     Soft Limit           Hard Limit           Units\nMax open files            1048576              1048576              files\n");
  t_check("limits numeric", lim.first == 1048576 && lim.second == 1048576);
  // 6. max open files unlimited
  lim = parse_max_open_files("Max open files            unlimited            unlimited            files\n");
  t_check("limits unlimited", lim.first == -1 && lim.second == -1);
  // 7. limits line missing
  lim = parse_max_open_files("Max processes             unlimited            unlimited            processes\n");
  t_check("limits not found", lim.first == 0 && lim.second == 0);
  // 8. state with parens inside comm
  t_check("state parse", parse_state("456 (a (b) c) R 1 2 3") == 'R');
  // 9. state with trailing spaces
  t_check("state basic", parse_state("12 (bash) S 1 2") == 'S');
  // 10. fmt_int
  t_check("fmt_int", fmt_int(3488) == "3.488" && fmt_int(1048576) == "1.048.576");
  // 11. fmt_human
  t_check("fmt_human", fmt_human(9223372036854775807LL) == "9.22E" && fmt_human(3488) == "3.488");
  // 12. json_escape
  t_check("json_escape", json_escape("a\"b\\c\nd") == "a\\\"b\\\\c\\nd");
  // 13. real /proc/sys/fs/file-nr parses
  fn = parse_file_nr(read_file("/proc/sys/fs/file-nr"));
  t_check("real file-nr", fn.ok && fn.allocated >= 0 && fn.max >= fn.allocated);
  // 14. real scan finds processes
  auto scan = scan_procs();
  bool any_fd = std::any_of(scan.procs.begin(), scan.procs.end(), [](const ProcFd& p) { return p.fds >= 0; });
  t_check("real proc scan", scan.procs.size() >= 1 && any_fd);
  // 15. snapshot consistency
  Snapshot s = take_snapshot();
  t_check("snapshot totals", s.scanned == static_cast<int>(s.scan.procs.size()) &&
                             s.total_fds >= 0 && s.avg_fds >= 0.0);
  // 16. JSON valid shape (starts with {, contains keys)
  std::string j = build_json(s);
  t_check("json shape", j.starts_with("{\n  \"system\"") && j.find("\"summary\"") != std::string::npos);
  // 17. bar clamp
  t_check("bar clamp", bar(0, 10, 5) == "....." && bar(10, 10, 5) == "|||||" && bar(7, 10, 5) == "||||.");
  // 18. state distribution does not crash on empty scan
  Snapshot empty;
  print_states(empty);

  std::cout << '\n' << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

}  // namespace fdwatch

// ── main (global scope) ────────────────────────────────────────────────────
int main(int argc, char** argv) {
  using namespace fdwatch;
  init_palette();
  int watch = 0, top_n = 10;
  long long min_fds = 0;
  bool json = false, selftest = false;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next_int = [&](const char* flag) -> long long {
      if (i + 1 < argc) return std::atoll(argv[++i]);
      std::cerr << flag << " requires a number\n";
      std::exit(2);
    };
    if (a == "--watch") watch = static_cast<int>(next_int("--watch"));
    else if (a == "--top") top_n = static_cast<int>(next_int("--top"));
    else if (a == "--min") min_fds = next_int("--min");
    else if (a == "--json") json = true;
    else if (a == "--no-color" || a == "-c") disable_color();
    else if (a == "--selftest") selftest = true;
    else if (a == "-h" || a == "--help") { print_help(argv[0]); return 0; }
    else { std::cerr << "opcion desconocida: " << a << " (usa --help)\n"; return 2; }
  }
  if (selftest) return run_selftest();
  if (top_n < 1) top_n = 10;

  if (json) {
    std::cout << build_json(take_snapshot());
    return 0;
  }
  if (watch > 0) {
    run_watch(watch, top_n, min_fds);
    return 0;
  }

  Snapshot s = take_snapshot();
  std::cout << P.bold << "  FD WATCH — Linux file descriptor usage" << P.rst << P.dim
            << "  (/proc/sys/fs/file-nr + /proc/<pid>/fd)" << P.rst << '\n';
  std::cout << P.dim << "  ------------------------------------------------------------------------------" << P.rst << '\n';
  print_system_line(s, false, 0.0, 0.0);
  print_states(s);
  std::cout << '\n';
  print_table(s, top_n, min_fds);
  return 0;
}
