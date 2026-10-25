// security.cpp - users, login, permission decisions, audit log (see security.hpp).
#include "security.hpp"

#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include "crypto.hpp"

static constexpr unsigned kIterations = 60000;   // PBKDF2 rounds (~0.1 s per check)
static constexpr int kLockAfter = 5;              // consecutive failures that lock an account

const char* to_string(Role r) {
  switch (r) {
    case Role::Admin: return "admin";
    case Role::Standard: return "standard";
    case Role::Guest: return "guest";
  }
  return "?";
}

bool parse_role(const std::string& s, Role& out) {
  if (s == "admin") out = Role::Admin;
  else if (s == "standard" || s == "user") out = Role::Standard;
  else if (s == "guest") out = Role::Guest;
  else return false;
  return true;
}

std::string group_of(Role r) {
  switch (r) {
    case Role::Admin: return "admin";
    case Role::Standard: return "users";
    case Role::Guest: return "guest";
  }
  return "users";
}

Security& Security::get() {
  static Security s;
  return s;
}

// ===========================================================================
// Paths
// ===========================================================================
static std::string exe_dir() {
  char buf[PATH_MAX];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
  if (n <= 0) return ".";
  buf[n] = 0;
  std::string s = buf;
  return s.substr(0, s.rfind('/'));
}

static bool is_dir(const std::string& p) {
  struct stat st;
  return stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

static std::string dirname_of(const std::string& abs) {
  size_t k = abs.rfind('/');
  return k == 0 ? "/" : abs.substr(0, k);
}

std::string Security::canon(const std::string& path) const {
  std::string p = path;
  if (p.empty()) p = ".";
  if (p[0] != '/') {
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof cwd)) return p;
    p = std::string(cwd) + "/" + p;
  }
  // lexical clean-up: //, /./ and /../
  std::vector<std::string> parts;
  std::stringstream ss(p);
  std::string c;
  while (std::getline(ss, c, '/')) {
    if (c.empty() || c == ".") continue;
    if (c == "..") { if (!parts.empty()) parts.pop_back(); continue; }
    parts.push_back(c);
  }
  // resolve symbolic links in the longest existing prefix
  std::string tail;
  while (!parts.empty()) {
    std::string pre;
    for (const auto& x : parts) pre += "/" + x;
    char real[PATH_MAX];
    if (realpath(pre.c_str(), real)) {
      std::string r = real;
      return r == "/" ? (tail.empty() ? "/" : tail) : r + tail;
    }
    tail = "/" + parts.back() + tail;
    parts.pop_back();
  }
  return tail.empty() ? "/" : tail;
}

bool Security::managed(const std::string& abs) const {
  return !fs_.empty() && (abs == fs_ || abs.compare(0, fs_.size() + 1, fs_ + "/") == 0);
}

bool Security::in_db(const std::string& abs) const {
  return !home_.empty() && (abs == home_ || abs.compare(0, home_.size() + 1, home_ + "/") == 0);
}

std::string Security::rel(const std::string& abs) const {
  if (managed(abs)) {
    std::string base = fs_.substr(fs_.rfind('/') + 1);
    return abs == fs_ ? base : base + abs.substr(fs_.size());
  }
  return abs;
}

std::string Security::home_of(const std::string& name) const { return fs_ + "/home/" + name; }

// ===========================================================================
// Set-up and persistence
// ===========================================================================
std::string Security::init() {
  const char* h = getenv("MYSHELL_HOME");
  const char* f = getenv("MYSHELL_FS");
  std::string base = exe_dir();
  home_ = h && *h ? h : base + "/.myshell";
  if (mkdir(home_.c_str(), 0700) < 0 && errno != EEXIST) return "cannot create " + home_ + ": " + strerror(errno);
  home_ = canon(home_);
  fs_ = canon(f && *f ? f : base + "/fs");
  passwd_path_ = home_ + "/passwd";
  meta_path_ = home_ + "/fsmeta";
  audit_path_ = home_ + "/audit.log";
  // for scripts: where the shell, its database and the managed tree are
  setenv("MYSHELL_DIR", canon(base).c_str(), 1);
  setenv("MYSHELL_HOME", home_.c_str(), 1);
  setenv("MYSHELL_FS", fs_.c_str(), 1);
  load_users();
  load_meta();
  return "";
}

void Security::load_users() {
  users_.clear();
  std::ifstream in(passwd_path_);
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::vector<std::string> f;
    std::stringstream ss(line);
    std::string x;
    while (std::getline(ss, x, ':')) f.push_back(x);
    if (f.size() < 8) continue;
    User u;
    u.name = f[0];
    if (!parse_role(f[1], u.role)) continue;
    u.iterations = (unsigned)strtoul(f[2].c_str(), nullptr, 10);
    u.salt = f[3];
    u.hash = f[4];
    u.failures = atoi(f[5].c_str());
    u.locked = f[6] == "1";
    u.last_login = atol(f[7].c_str());
    users_[u.name] = u;
  }
}

void Security::save_users() {
  std::string tmp = passwd_path_ + ".tmp";
  int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) return;
  std::string out = "# myshell users: name:role:iterations:salt:pbkdf2-sha256:failures:locked:last_login\n";
  for (const auto& [n, u] : users_)
    out += u.name + ":" + to_string(u.role) + ":" + std::to_string(u.iterations) + ":" + u.salt + ":" + u.hash + ":" +
           std::to_string(u.failures) + ":" + (u.locked ? "1" : "0") + ":" + std::to_string(u.last_login) + "\n";
  if (write(fd, out.data(), out.size()) < 0) {}
  close(fd);
  rename(tmp.c_str(), passwd_path_.c_str());
}

// The metadata is an append-only journal, so a forked child (a redirection in
// a background job, a pipeline stage) can record a file it created without
// racing the shell: every process appends, and everyone re-reads it when it
// has grown.
void Security::load_meta() {
  meta_.clear();
  std::ifstream in(meta_path_);
  std::string line;
  while (std::getline(in, line)) {
    std::vector<std::string> f;
    std::stringstream ss(line);
    std::string x;
    while (std::getline(ss, x, '\t')) f.push_back(x);
    if (f.size() == 5 && f[0] == "set") {
      FileMeta m;
      m.mode = (unsigned)strtoul(f[1].c_str(), nullptr, 8);
      m.owner = f[2];
      m.group = f[3];
      m.recorded = true;
      meta_[f[4]] = m;
    } else if (f.size() == 2 && f[0] == "del") {
      for (auto it = meta_.begin(); it != meta_.end();)
        it = (it->first == f[1] || it->first.compare(0, f[1].size() + 1, f[1] + "/") == 0) ? meta_.erase(it) : std::next(it);
    } else if (f.size() == 3 && f[0] == "mv") {
      std::map<std::string, FileMeta> moved;
      for (auto it = meta_.begin(); it != meta_.end();) {
        if (it->first == f[1] || it->first.compare(0, f[1].size() + 1, f[1] + "/") == 0) {
          moved[f[2] + it->first.substr(f[1].size())] = it->second;
          it = meta_.erase(it);
        } else {
          ++it;
        }
      }
      for (auto& [k, v] : moved) meta_[k] = v;
    }
  }
  struct stat st;
  meta_size_ = stat(meta_path_.c_str(), &st) == 0 ? (long)st.st_size : 0;
}

void Security::refresh_meta() {
  struct stat st;
  long sz = stat(meta_path_.c_str(), &st) == 0 ? (long)st.st_size : 0;
  if (sz != meta_size_) load_meta();
}

void Security::append_meta(const std::string& line) {
  int fd = open(meta_path_.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (fd < 0) return;
  std::string l = line + "\n";
  if (write(fd, l.data(), l.size()) < 0) {}
  close(fd);
  load_meta();
}

static std::string key_of(const std::string& fs, const std::string& abs) {
  return abs == fs ? "" : abs.substr(fs.size() + 1);
}

static void real_mode(const std::string& abs, unsigned mode, bool dir) {
  // Keep the real permission bits usable by the shell's own (single) Unix
  // user: the shell decides access; the kernel only needs to let it through.
  unsigned m = (mode & 07777) | (dir ? 0700 : 0600);
  if (!dir && (mode & 0111)) m |= 0100;
  chmod(abs.c_str(), m & 07777);
}

void Security::set_meta(const std::string& path, const std::string& owner, const std::string& group, unsigned mode) {
  std::string abs = canon(path);
  if (!managed(abs)) return;
  char m[16];
  snprintf(m, sizeof m, "%04o", mode & 07777);
  append_meta("set\t" + std::string(m) + "\t" + owner + "\t" + group + "\t" + key_of(fs_, abs));
  real_mode(abs, mode, is_dir(abs));
}

void Security::record_new(const std::string& path, bool dir) {
  std::string abs = canon(path);
  if (!managed(abs) || !logged_in()) return;
  const User* u = current();
  set_meta(abs, u->name, group_of(u->role), dir ? 0755 : 0644);
}

// The directory entry itself: a symbolic link is not followed (removing a
// link removes the link, not its target).
std::string Security::entry(const std::string& path) const {
  const Security& sec = *this;
  struct stat st;
  if (lstat(path.c_str(), &st) == 0 && S_ISLNK(st.st_mode)) {
    std::string p = path;
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    size_t s = p.rfind('/');
    std::string dir = s == std::string::npos ? "." : (s == 0 ? "/" : p.substr(0, s));
    std::string d = sec.canon(dir);
    return (d == "/" ? "" : d) + "/" + p.substr(s == std::string::npos ? 0 : s + 1);
  }
  return sec.canon(path);
}

void Security::forget(const std::string& path) {
  std::string abs = entry(path);
  if (managed(abs)) append_meta("del\t" + key_of(fs_, abs));
}

void Security::moved(const std::string& from, const std::string& to) {
  std::string a = entry(from), b = entry(to);
  if (managed(a) && managed(b)) append_meta("mv\t" + key_of(fs_, a) + "\t" + key_of(fs_, b));
  else if (managed(a)) forget(a);
  else if (managed(b)) record_new(b, is_dir(b));
}

FileMeta Security::meta(const std::string& abs) {
  refresh_meta();
  std::string k = key_of(fs_, abs);
  auto it = meta_.find(k);
  if (it != meta_.end()) return it->second;
  // Not recorded (e.g. created by an external program): it belongs to the
  // owner of the nearest recorded directory above, with default modes.
  FileMeta m;
  m.owner = "admin";
  m.group = "admin";
  std::string up = k;
  while (!up.empty()) {
    size_t s = up.rfind('/');
    up = s == std::string::npos ? "" : up.substr(0, s);
    auto p = meta_.find(up);
    if (p != meta_.end()) { m.owner = p->second.owner; m.group = p->second.group; break; }
  }
  m.mode = is_dir(abs) ? 0755 : 0644;
  m.recorded = false;
  return m;
}

// ===========================================================================
// Users and sessions
// ===========================================================================
std::string Security::password_problem(const std::string& pw) {
  if (pw.size() < 8) return "a password needs at least 8 characters";
  bool letter = false, digit = false;
  for (char c : pw) {
    if (isalpha((unsigned char)c)) letter = true;
    if (isdigit((unsigned char)c)) digit = true;
    if (c == ':' || c == '\n') return "a password may not contain ':' or a newline";
  }
  if (!letter || !digit) return "a password needs both letters and digits";
  return "";
}

static bool valid_name(const std::string& n) {
  if (n.empty() || n.size() > 16 || !(islower((unsigned char)n[0]) || n[0] == '_')) return false;
  for (char c : n)
    if (!(islower((unsigned char)c) || isdigit((unsigned char)c) || c == '_' || c == '-')) return false;
  return true;
}

Security::Auth Security::authenticate(const std::string& name, const std::string& password) {
  load_users();                                       // another shell may have changed it
  auto it = users_.find(name);
  if (it == users_.end()) {
    crypto::pbkdf2_sha256(password, std::vector<uint8_t>(16, 0), kIterations);   // same cost: no user enumeration by timing
    audit("LOGIN-FAIL unknown user '" + name + "'");
    return Auth::NoSuchUser;
  }
  User& u = it->second;
  std::vector<uint8_t> h = crypto::pbkdf2_sha256(password, crypto::from_hex(u.salt), u.iterations);
  bool good = crypto::equal_ct(h, crypto::from_hex(u.hash));
  if (u.locked) {
    audit("LOGIN-FAIL " + name + ": account is locked");
    return Auth::Locked;
  }
  if (!good) {
    u.failures++;
    if (u.failures >= kLockAfter) {
      u.locked = true;
      audit("LOCK " + name + ": " + std::to_string(u.failures) + " consecutive failed logins");
    }
    audit("LOGIN-FAIL " + name + ": wrong password (" + std::to_string(u.failures) + " in a row)");
    save_users();
    return Auth::Bad;
  }
  failures_before_login = u.failures;
  previous_login = u.last_login;
  u.failures = 0;
  u.last_login = (long)time(nullptr);
  save_users();
  return Auth::Ok;
}

void Security::begin_session(const std::string& name) {
  session_ = name;
  audit("LOGIN " + name + " (role " + to_string(users_[name].role) + ")");
}

void Security::end_session() {
  if (!session_.empty()) audit("LOGOUT " + session_);
  session_.clear();
}

const User* Security::current() const {
  auto it = users_.find(session_);
  return it == users_.end() ? nullptr : &it->second;
}

std::string Security::add_user(const std::string& name, Role role, const std::string& password) {
  load_users();
  if (!valid_name(name)) return "user names are 1-16 characters: lower-case letters, digits, '_' and '-'";
  if (users_.count(name)) return "user '" + name + "' already exists";
  std::string p = password_problem(password);
  if (!p.empty()) return p;
  User u;
  u.name = name;
  u.role = role;
  u.iterations = kIterations;
  std::vector<uint8_t> salt = crypto::random_bytes(16);
  u.salt = crypto::to_hex(salt);
  u.hash = crypto::to_hex(crypto::pbkdf2_sha256(password, salt, kIterations));
  users_[name] = u;
  save_users();
  if (is_dir(fs_ + "/home")) {
    std::string h = home_of(name);
    mkdir(h.c_str(), 0700);
    set_meta(h, name, group_of(role), role == Role::Guest ? 0755 : 0700);
  }
  audit("USERADD " + name + " role " + to_string(role) + " by " + session_);
  return "";
}

std::string Security::del_user(const std::string& name) {
  load_users();
  auto it = users_.find(name);
  if (it == users_.end()) return "no user '" + name + "'";
  if (name == session_) return "you cannot delete the account you are logged in with";
  if (it->second.role == Role::Admin) {
    int admins = 0;
    for (const auto& [n, u] : users_) admins += u.role == Role::Admin;
    if (admins <= 1) return "'" + name + "' is the last admin";
  }
  users_.erase(it);
  save_users();
  audit("USERDEL " + name + " by " + session_);
  return "";
}

std::string Security::set_password(const std::string& name, const std::string& password) {
  load_users();
  auto it = users_.find(name);
  if (it == users_.end()) return "no user '" + name + "'";
  std::string p = password_problem(password);
  if (!p.empty()) return p;
  std::vector<uint8_t> salt = crypto::random_bytes(16);
  it->second.salt = crypto::to_hex(salt);
  it->second.iterations = kIterations;
  it->second.hash = crypto::to_hex(crypto::pbkdf2_sha256(password, salt, kIterations));
  save_users();
  audit("PASSWD " + name + " by " + session_);
  return "";
}

std::string Security::set_role(const std::string& name, Role role) {
  load_users();
  auto it = users_.find(name);
  if (it == users_.end()) return "no user '" + name + "'";
  if (it->second.role == Role::Admin && role != Role::Admin) {
    int admins = 0;
    for (const auto& [n, u] : users_) admins += u.role == Role::Admin;
    if (admins <= 1) return "'" + name + "' is the last admin";
  }
  it->second.role = role;
  save_users();
  audit("USERMOD " + name + " role " + to_string(role) + " by " + session_);
  return "";
}

std::string Security::unlock(const std::string& name) {
  load_users();
  auto it = users_.find(name);
  if (it == users_.end()) return "no user '" + name + "'";
  it->second.locked = false;
  it->second.failures = 0;
  save_users();
  audit("UNLOCK " + name + " by " + session_);
  return "";
}

// ===========================================================================
// Permission decisions
// ===========================================================================
std::string Security::mode_string(unsigned mode, bool dir) {
  std::string s = dir ? "d" : "-";
  for (int sh = 6; sh >= 0; sh -= 3) {
    s += (mode >> sh) & 4 ? 'r' : '-';
    s += (mode >> sh) & 2 ? 'w' : '-';
    s += (mode >> sh) & 1 ? 'x' : '-';
  }
  if (mode & 01000) s[9] = (mode & 1) ? 't' : 'T';
  return s;
}

static std::string perm_letters(int p) {
  std::string s;
  s += p & kRead ? 'r' : '-';
  s += p & kWrite ? 'w' : '-';
  s += p & kExec ? 'x' : '-';
  return s;
}

Decision Security::bits(const std::string& abs, int perms, const std::string& what) {
  const User* u = current();
  FileMeta m = meta(abs);
  int shift;
  const char* cls;
  if (u->name == m.owner) { shift = 6; cls = "owner"; }
  else if (group_of(u->role) == m.group) { shift = 3; cls = "group"; }
  else { shift = 0; cls = "others"; }
  int have = (int)((m.mode >> shift) & 7);
  Decision d;
  d.ok = (have & perms) == perms;
  d.why = u->name + " is '" + cls + "' for " + rel(abs) + " (" + m.owner + ":" + m.group + " " +
          mode_string(m.mode, is_dir(abs)) + "): " + cls + (shift == 0 ? " have " : " has ") + perm_letters(have) + ", " + what + " needs " +
          perm_letters(perms);
  return d;
}

Decision Security::traverse(const std::string& abs) {
  // every directory from the root of the managed tree down to the parent
  std::string d = fs_;
  std::string rest = abs.size() > fs_.size() ? abs.substr(fs_.size() + 1) : "";
  size_t pos = 0;
  while (true) {
    size_t s = rest.find('/', pos);
    if (s == std::string::npos) break;                // what remains is the target itself
    Decision x = bits(d, kExec, "passing through");
    if (!x.ok) return x;
    d += "/" + rest.substr(pos, s - pos);
    pos = s + 1;
  }
  if (abs != fs_) {
    Decision x = bits(d, kExec, "passing through");
    if (!x.ok) return x;
  }
  return Decision{};
}

Decision Security::check(const std::string& path, int perms, const std::string& op) {
  Decision d;
  const User* u = current();
  if (!u) { d.ok = false; d.why = "not logged in"; return d; }
  std::string abs = canon(path);
  if (in_db(abs)) {
    d.ok = u->role == Role::Admin && !(perms & kWrite);
    d.why = d.ok ? "admin may read the security database" : "the security database is reachable only through the user-management commands";
    return d;
  }
  if (!managed(abs)) {
    d.ok = !(perms & kWrite) || u->role == Role::Admin;
    d.why = d.ok ? "outside the managed file system: the real Unix permissions apply"
                 : "outside the managed file system only admin may modify files (" + u->name + " is " + to_string(u->role) + ")";
    return d;
  }
  if ((perms & kWrite) && u->role == Role::Guest) {
    d.ok = false;
    d.why = "role guest is read-only (" + op + " would modify a file)";
    return d;
  }
  if (u->role == Role::Admin) {
    FileMeta m = meta(abs);
    if ((perms & kExec) && !is_dir(abs) && !(m.mode & 0111)) {
      d.ok = false;
      d.why = rel(abs) + " (" + mode_string(m.mode, false) + ") has no execute bit; even admin cannot run it";
      return d;
    }
    d.why = "admin may read and write every file";
    return d;
  }
  d = traverse(abs);
  if (!d.ok) return d;
  return bits(abs, perms, op);
}

Decision Security::check_create(const std::string& path, const std::string& op) {
  Decision d;
  const User* u = current();
  if (!u) { d.ok = false; d.why = "not logged in"; return d; }
  std::string abs = entry(path);
  if (in_db(abs)) { d.ok = false; d.why = "the security database is reachable only through the user-management commands"; return d; }
  if (!managed(abs)) {
    d.ok = u->role == Role::Admin;
    d.why = d.ok ? "admin may create files outside the managed file system"
                 : "outside the managed file system only admin may create files (" + u->name + " is " + to_string(u->role) + ")";
    return d;
  }
  if (u->role == Role::Guest) { d.ok = false; d.why = "role guest is read-only (" + op + " would change a directory)"; return d; }
  if (u->role == Role::Admin) { d.why = "admin may change every directory"; return d; }
  d = traverse(abs);
  if (!d.ok) return d;
  return bits(dirname_of(abs), kWrite | kExec, op + " (it changes the directory)");
}

Decision Security::check_delete(const std::string& path, const std::string& op) {
  Decision d = check_create(path, op);
  if (!d.ok || is_admin()) return d;
  std::string abs = entry(path);
  if (!managed(abs)) return d;
  FileMeta dir = meta(dirname_of(abs)), f = meta(abs);
  if ((dir.mode & 01000) && f.owner != user() && dir.owner != user()) {
    d.ok = false;
    d.why = rel(dirname_of(abs)) + " has the sticky bit (" + mode_string(dir.mode, true) + "): only the owner of " +
            rel(abs) + " (" + f.owner + ") may delete or rename it";
  }
  return d;
}

Decision Security::check_chmod(const std::string& path) {
  Decision d;
  std::string abs = canon(path);
  if (in_db(abs)) { d.ok = false; d.why = "the security database cannot be changed with chmod"; return d; }
  if (is_admin()) { d.why = "admin may change any mode"; return d; }
  if (!managed(abs)) { d.ok = false; d.why = "outside the managed file system only admin may change modes"; return d; }
  if (current() && current()->role == Role::Guest) { d.ok = false; d.why = "role guest is read-only"; return d; }
  Decision t = traverse(abs);
  if (!t.ok) return t;
  FileMeta m = meta(abs);
  d.ok = m.owner == user();
  d.why = d.ok ? user() + " owns " + rel(abs) : "only the owner of " + rel(abs) + " (" + m.owner + ") or admin may change its mode";
  return d;
}

Decision Security::check_chown(const std::string& path) {
  Decision d;
  std::string abs = canon(path);
  d.ok = is_admin() && managed(abs);
  d.why = d.ok ? "admin may change owners" : (managed(abs) ? "only admin may change the owner of a file" : "chown applies to the managed file system only");
  return d;
}

Decision Security::require_admin(const std::string& op) {
  Decision d;
  const User* u = current();
  d.ok = u && u->role == Role::Admin;
  d.why = d.ok ? "admin" : op + " requires the admin role (" + (u ? u->name + " is " + to_string(u->role) : std::string("not logged in")) + ")";
  return d;
}

bool Security::allow(const Decision& d, const char* cmd, const std::string& path) {
  if (d.ok) return true;
  if (path.empty()) fprintf(stderr, "%s: permission denied: %s\n", cmd, d.why.c_str());
  else fprintf(stderr, "%s: %s: permission denied: %s\n", cmd, path.c_str(), d.why.c_str());
  audit("DENY " + (session_.empty() ? std::string("-") : session_) + " " + cmd + (path.empty() ? "" : " " + path) + ": " + d.why);
  return false;
}

bool Security::parse_mode(const std::string& spec, unsigned old, bool dir, unsigned& out) {
  if (spec.empty()) return false;
  if (isdigit((unsigned char)spec[0])) {
    if (spec.size() > 4) return false;
    for (char c : spec) if (c < '0' || c > '7') return false;
    out = (unsigned)strtoul(spec.c_str(), nullptr, 8);
    return true;
  }
  unsigned m = old;
  std::stringstream ss(spec);
  std::string clause;
  while (std::getline(ss, clause, ',')) {
    size_t i = 0;
    unsigned who = 0;
    for (; i < clause.size() && strchr("ugoa", clause[i]); ++i)
      who |= clause[i] == 'u' ? 0700 : clause[i] == 'g' ? 0070 : clause[i] == 'o' ? 0007 : 0777;
    if (!who) who = 0777;
    if (i >= clause.size() || !strchr("+-=", clause[i])) return false;
    char op = clause[i++];
    unsigned bitsv = 0;
    bool sticky = false;
    for (; i < clause.size(); ++i) {
      if (clause[i] == 'r') bitsv |= 0444;
      else if (clause[i] == 'w') bitsv |= 0222;
      else if (clause[i] == 'x') bitsv |= 0111;
      else if (clause[i] == 't') sticky = true;
      else return false;
    }
    bitsv &= who;
    if (op == '+') { m |= bitsv; if (sticky) m |= 01000; }
    else if (op == '-') { m &= ~bitsv; if (sticky) m &= ~01000u; }
    else { m = (m & ~who) | bitsv; if (sticky) m |= 01000; }
  }
  (void)dir;
  out = m;
  return true;
}

// ===========================================================================
// Audit log
// ===========================================================================
void Security::audit(const std::string& event) {
  if (audit_path_.empty()) return;
  int fd = open(audit_path_.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (fd < 0) return;
  char when[32];
  time_t t = time(nullptr);
  struct tm tmv;
  localtime_r(&t, &tmv);
  strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", &tmv);
  std::string l = std::string(when) + " " + event + "\n";
  if (write(fd, l.data(), l.size()) < 0) {}
  close(fd);
}

std::vector<std::string> Security::audit_tail(size_t n) const {
  std::vector<std::string> all;
  std::ifstream in(audit_path_);
  std::string line;
  while (std::getline(in, line)) all.push_back(line);
  if (all.size() > n) all.erase(all.begin(), all.end() - (long)n);
  return all;
}

// ===========================================================================
// Demo set-up: users and a small file tree with interesting permissions
// ===========================================================================
static bool write_file(const std::string& p, const std::string& content) {
  int fd = open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return false;
  bool ok = write(fd, content.data(), content.size()) == (ssize_t)content.size();
  close(fd);
  return ok;
}

static int remove_entry(const char* p, const struct stat*, int, struct FTW*) { return remove(p); }

std::string Security::setup_demo() {
  // users (the passwords are for the demonstration only)
  users_.clear();
  unlink(passwd_path_.c_str());
  unlink(meta_path_.c_str());
  unlink(audit_path_.c_str());
  // a clean tree: only the demo's own top-level directories are removed
  for (const char* d : {"/system", "/bin", "/logs", "/home", "/shared"})
    nftw((fs_ + d).c_str(), remove_entry, 16, FTW_DEPTH | FTW_PHYS);
  meta_.clear();
  meta_size_ = -1;
  std::string saved = session_;
  session_ = "setup";
  struct { const char* name; Role role; const char* pw; } demo[] = {
      {"admin", Role::Admin, "admin123"}, {"alice", Role::Standard, "alice123"},
      {"bob", Role::Standard, "bob12345"}, {"guest", Role::Guest, "guest123"}};
  // the tree
  for (const char* d : {"", "/system", "/bin", "/logs", "/home", "/home/admin", "/home/alice", "/home/bob",
                        "/home/guest", "/shared"})
    if (mkdir((fs_ + d).c_str(), 0755) < 0 && errno != EEXIST) return "cannot create " + fs_ + d + ": " + strerror(errno);
  for (auto& u : demo) {
    std::string e = add_user(u.name, u.role, u.pw);
    if (!e.empty()) return e;
  }
  auto file = [&](const char* p, const std::string& content, const char* owner, const char* group, unsigned mode) {
    write_file(fs_ + p, content);
    set_meta(fs_ + p, owner, group, mode);
  };
  set_meta(fs_, "admin", "admin", 0755);
  set_meta(fs_ + "/system", "admin", "admin", 0755);
  set_meta(fs_ + "/bin", "admin", "admin", 0755);
  set_meta(fs_ + "/logs", "admin", "admin", 0755);
  set_meta(fs_ + "/home", "admin", "admin", 0755);
  set_meta(fs_ + "/shared", "admin", "users", 01775);
  file("/system/config", "# myshell system configuration\nmax_users=16\nscheduler=rr\nquantum_ms=100\nlog_level=info\n",
       "admin", "admin", 0644);
  file("/system/secret.key", "SECRET-KEY-7f3a-only-for-admin\n", "admin", "admin", 0600);
  file("/system/maintenance.sh", "#!/bin/sh\necho \"maintenance: rotating logs (run by $USER)\"\n", "admin", "admin", 0750);
  file("/bin/hello.sh", "#!/bin/sh\necho \"hello from a shared tool, run by $USER\"\n", "admin", "admin", 0755);
  file("/logs/app.log",
       "2026-10-25 08:01 info  service started\n2026-10-25 08:02 error disk quota exceeded on /home\n"
       "2026-10-25 08:03 warn  slow response from scheduler\n2026-10-25 08:04 error authentication failed for bob\n"
       "2026-10-25 08:05 info  backup completed\n2026-10-25 08:06 error connection reset by peer\n"
       "2026-10-25 08:07 info  user alice logged in\n2026-10-25 08:08 error authentication failed for bob\n"
       "2026-10-25 08:09 warn  memory usage at 85%\n2026-10-25 08:10 info  user bob logged in\n",
       "admin", "admin", 0644);
  file("/home/alice/notes.txt", "meeting notes: ship the pipeline feature on Friday\n", "alice", "users", 0640);
  file("/home/alice/diary.txt", "private: only alice may read this\n", "alice", "users", 0600);
  file("/home/bob/report.sh", "#!/bin/sh\necho \"bob's weekly report: all systems nominal\"\n", "bob", "users", 0644);
  file("/shared/team.txt", "team board: alice and bob may both edit this file\n", "alice", "users", 0664);
  file("/shared/readme.txt", "shared/ is writable by group users; the sticky bit protects each file's owner\n",
       "admin", "admin", 0644);
  session_ = saved;
  unlink(audit_path_.c_str());
  audit("SETUP demo users admin, alice, bob, guest and the file tree " + fs_);
  return "";
}
