// security_builtin.cpp - Deliverable 4 built-ins: sessions, users, permissions.
//
//   login [USER]          switch to another user (asks for the password)
//   logout                end the session (back to the login prompt)
//   whoami | id           who is logged in, with role, group and home
//   users                 list the users (admin also sees failures and locks)
//   useradd NAME [-r ROLE] | userdel NAME | usermod NAME -r ROLE | unlock NAME   (admin)
//   passwd [USER]         change a password (your own, or anyone's as admin)
//   chmod MODE FILE...    octal (640) or symbolic (u+x,g-w,o=r,+t) - owner or admin
//   chown USER[:GROUP] FILE...   admin only
//   access FILE...        explain which of read / write / execute / delete you may do, and why
//   audit [N]             the last N lines of the security log (admin)
//   cp SRC DST | mv SRC DST     copy / rename, with permission checks
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "builtins.hpp"
#include "security.hpp"
#include "shell.hpp"

using Args = std::vector<std::string>;

namespace {

bool need_admin(const char* cmd) {
  Security& sec = Security::get();
  return sec.allow(sec.require_admin(cmd), cmd, "");
}

bool new_password(Shell& sh, const char* cmd, std::string& out) {
  std::string a, b;
  if (!sh.read_secret("new password: ", a) || !sh.read_secret("retype new password: ", b)) return false;
  if (a != b) { fprintf(stderr, "%s: the passwords do not match\n", cmd); return false; }
  std::string p = Security::password_problem(a);
  if (!p.empty()) { fprintf(stderr, "%s: %s\n", cmd, p.c_str()); return false; }
  out = a;
  return true;
}

bool is_dir(const std::string& p) {
  struct stat st;
  return stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool exists(const std::string& p) {
  struct stat st;
  return stat(p.c_str(), &st) == 0;
}

}  // namespace

int builtin_login(Shell& sh, const Args& a) {
  if (a.size() > 2) { fprintf(stderr, "login: usage: login [USER]\n"); return 2; }
  std::string name = a.size() == 2 ? a[1] : "";
  if (name.empty() && !sh.read_input_line("login: ", name)) return 1;
  Security& sec = Security::get();
  std::string before = sec.user();
  if (!sh.login_as(name)) return 1;
  int theirs = 0;
  for (Job* j : sh.jobs.active()) theirs += j->owner == before && !j->finished();
  if (!before.empty() && before != name && theirs)
    printf("(%d job(s) of %s keep running; log in as %s again to control them)\n", theirs, before.c_str(), before.c_str());
  return 0;
}

int builtin_logout(Shell& sh, const Args& a) {
  if (a.size() > 1) { fprintf(stderr, "logout: too many arguments\n"); return 2; }
  Security& sec = Security::get();
  sh.reap_children(true);
  int n = 0;
  for (Job* j : sh.jobs.active())                 // the session's jobs end with it (a hang-up)
    if (j->owner == sec.user() && !j->finished()) {
      kill(-j->pgid, SIGHUP);
      kill(-j->pgid, SIGCONT);
      ++n;
    }
  if (n) printf("logout: %d job(s) of %s hung up (SIGHUP)\n", n, sec.user().c_str());
  printf("%s logged out\n", sec.user().c_str());
  sec.end_session();
  sh.logout_requested = true;
  return 0;
}

int builtin_whoami(Shell&, const Args&) {
  Security& sec = Security::get();
  printf("%s\n", sec.user().c_str());
  return 0;
}

int builtin_id(Shell&, const Args& a) {
  Security& sec = Security::get();
  std::string who = a.size() > 1 ? a[1] : sec.user();
  auto it = sec.users().find(who);
  if (it == sec.users().end()) { fprintf(stderr, "id: no such user '%s'\n", who.c_str()); return 1; }
  const User& u = it->second;
  printf("user=%s role=%s group=%s home=%s%s\n", u.name.c_str(), to_string(u.role), group_of(u.role).c_str(),
         sec.rel(sec.home_of(u.name)).c_str(), u.locked ? " (LOCKED)" : "");
  return 0;
}

int builtin_users(Shell&, const Args&) {
  Security& sec = Security::get();
  bool admin = sec.is_admin();
  if (admin) printf("  %-10s %-9s %-7s %-8s %-6s %s\n", "USER", "ROLE", "GROUP", "FAILURES", "LOCKED", "LAST LOGIN");
  else printf("  %-10s %-9s %s\n", "USER", "ROLE", "GROUP");
  for (const auto& [n, u] : sec.users()) {
    if (!admin) { printf("  %-10s %-9s %s\n", n.c_str(), to_string(u.role), group_of(u.role).c_str()); continue; }
    char when[32] = "never";
    if (u.last_login) {
      time_t t = (time_t)u.last_login;
      struct tm tmv;
      localtime_r(&t, &tmv);
      strftime(when, sizeof when, "%Y-%m-%d %H:%M", &tmv);
    }
    printf("  %-10s %-9s %-7s %-8d %-6s %s%s\n", n.c_str(), to_string(u.role), group_of(u.role).c_str(), u.failures,
           u.locked ? "yes" : "no", when, n == sec.user() ? "   <- you" : "");
  }
  return 0;
}

int builtin_useradd(Shell& sh, const Args& a) {
  if (!need_admin("useradd")) return 1;
  Role r = Role::Standard;
  if (!(a.size() == 2 || (a.size() == 4 && a[2] == "-r" && parse_role(a[3], r)))) {
    fprintf(stderr, "useradd: usage: useradd NAME [-r admin|standard|guest]\n");
    return 2;
  }
  std::string pw;
  if (!new_password(sh, "useradd", pw)) return 1;
  std::string e = Security::get().add_user(a[1], r, pw);
  if (!e.empty()) { fprintf(stderr, "useradd: %s\n", e.c_str()); return 1; }
  printf("user '%s' added (role %s, home %s)\n", a[1].c_str(), to_string(r),
         Security::get().rel(Security::get().home_of(a[1])).c_str());
  return 0;
}

int builtin_userdel(Shell&, const Args& a) {
  if (!need_admin("userdel")) return 1;
  if (a.size() != 2) { fprintf(stderr, "userdel: usage: userdel NAME\n"); return 2; }
  std::string e = Security::get().del_user(a[1]);
  if (!e.empty()) { fprintf(stderr, "userdel: %s\n", e.c_str()); return 1; }
  printf("user '%s' deleted (their files keep their owner)\n", a[1].c_str());
  return 0;
}

int builtin_usermod(Shell&, const Args& a) {
  if (!need_admin("usermod")) return 1;
  Role r;
  if (a.size() != 4 || a[2] != "-r" || !parse_role(a[3], r)) {
    fprintf(stderr, "usermod: usage: usermod NAME -r admin|standard|guest\n");
    return 2;
  }
  std::string e = Security::get().set_role(a[1], r);
  if (!e.empty()) { fprintf(stderr, "usermod: %s\n", e.c_str()); return 1; }
  printf("user '%s' now has role %s\n", a[1].c_str(), to_string(r));
  return 0;
}

int builtin_unlock(Shell&, const Args& a) {
  if (!need_admin("unlock")) return 1;
  if (a.size() != 2) { fprintf(stderr, "unlock: usage: unlock NAME\n"); return 2; }
  std::string e = Security::get().unlock(a[1]);
  if (!e.empty()) { fprintf(stderr, "unlock: %s\n", e.c_str()); return 1; }
  printf("account '%s' unlocked\n", a[1].c_str());
  return 0;
}

int builtin_passwd(Shell& sh, const Args& a) {
  Security& sec = Security::get();
  if (a.size() > 2) { fprintf(stderr, "passwd: usage: passwd [USER]\n"); return 2; }
  std::string who = a.size() == 2 ? a[1] : sec.user();
  if (who != sec.user()) {
    if (!need_admin("passwd")) return 1;
  } else {
    std::string old;
    if (!sh.read_secret("current password: ", old)) return 1;
    if (sec.authenticate(who, old) != Security::Auth::Ok) {
      fprintf(stderr, "passwd: authentication failed\n");
      return 1;
    }
  }
  std::string pw;
  if (!new_password(sh, "passwd", pw)) return 1;
  std::string e = sec.set_password(who, pw);
  if (!e.empty()) { fprintf(stderr, "passwd: %s\n", e.c_str()); return 1; }
  printf("password for '%s' changed\n", who.c_str());
  return 0;
}

int builtin_chmod(Shell&, const Args& a) {
  if (a.size() < 3) { fprintf(stderr, "chmod: usage: chmod MODE FILE...   (MODE: 640 or u+x,g-w,o=r,+t)\n"); return 2; }
  Security& sec = Security::get();
  int rc = 0;
  for (size_t i = 2; i < a.size(); ++i) {
    const std::string& f = a[i];
    if (!exists(f)) { fprintf(stderr, "chmod: cannot access '%s': %s\n", f.c_str(), strerror(ENOENT)); rc = 1; continue; }
    if (!sec.allow(sec.check_chmod(f), "chmod", f)) { rc = 1; continue; }
    std::string abs = sec.canon(f);
    bool dir = is_dir(abs);
    if (!sec.managed(abs)) {                      // admin, outside the managed tree: the real mode
      struct stat st;
      stat(abs.c_str(), &st);
      unsigned m;
      if (!Security::parse_mode(a[1], st.st_mode & 07777, dir, m)) { fprintf(stderr, "chmod: invalid mode '%s'\n", a[1].c_str()); return 2; }
      if (::chmod(abs.c_str(), m) < 0) { fprintf(stderr, "chmod: %s: %s\n", f.c_str(), strerror(errno)); rc = 1; }
      continue;
    }
    FileMeta m = sec.meta(abs);
    unsigned nm;
    if (!Security::parse_mode(a[1], m.mode, dir, nm)) { fprintf(stderr, "chmod: invalid mode '%s'\n", a[1].c_str()); return 2; }
    sec.set_meta(abs, m.owner, m.group, nm);
    printf("%s: %s -> %s\n", sec.rel(abs).c_str(), Security::mode_string(m.mode, dir).c_str(),
           Security::mode_string(nm, dir).c_str());
  }
  return rc;
}

int builtin_chown(Shell&, const Args& a) {
  if (a.size() < 3) { fprintf(stderr, "chown: usage: chown USER[:GROUP] FILE...\n"); return 2; }
  Security& sec = Security::get();
  std::string owner = a[1], group;
  size_t c = owner.find(':');
  if (c != std::string::npos) { group = owner.substr(c + 1); owner = owner.substr(0, c); }
  auto it = sec.users().find(owner);
  if (it == sec.users().end()) { fprintf(stderr, "chown: no such user '%s'\n", owner.c_str()); return 1; }
  if (group.empty()) group = group_of(it->second.role);
  if (group != "admin" && group != "users" && group != "guest") {
    fprintf(stderr, "chown: no such group '%s' (admin, users, guest)\n", group.c_str());
    return 1;
  }
  int rc = 0;
  for (size_t i = 2; i < a.size(); ++i) {
    if (!exists(a[i])) { fprintf(stderr, "chown: cannot access '%s': %s\n", a[i].c_str(), strerror(ENOENT)); rc = 1; continue; }
    if (!sec.allow(sec.check_chown(a[i]), "chown", a[i])) { rc = 1; continue; }
    std::string abs = sec.canon(a[i]);
    FileMeta m = sec.meta(abs);
    sec.set_meta(abs, owner, group, m.mode);
    printf("%s: owner %s:%s -> %s:%s\n", sec.rel(abs).c_str(), m.owner.c_str(), m.group.c_str(), owner.c_str(), group.c_str());
  }
  return rc;
}

int builtin_access(Shell&, const Args& a) {
  if (a.size() < 2) { fprintf(stderr, "access: usage: access FILE...\n"); return 2; }
  Security& sec = Security::get();
  for (size_t i = 1; i < a.size(); ++i) {
    std::string abs = sec.canon(a[i]);
    bool e = exists(abs);
    printf("%s (as %s, role %s)%s\n", sec.rel(abs).c_str(), sec.user().c_str(), to_string(sec.current()->role),
           e ? "" : ": does not exist");
    if (sec.managed(abs) && e) {
      FileMeta m = sec.meta(abs);
      printf("  owner %s, group %s, mode %s%s\n", m.owner.c_str(), m.group.c_str(),
             Security::mode_string(m.mode, is_dir(abs)).c_str(), m.recorded ? "" : " (not recorded: inherited)");
    }
    struct { const char* what; Decision d; } rows[4];
    int n = 0;
    if (e) {
      rows[n++] = {"read   ", sec.check(abs, kRead, "reading")};
      rows[n++] = {"write  ", sec.check(abs, kWrite, "writing")};
      rows[n++] = {"execute", sec.check(abs, kExec, is_dir(abs) ? "entering it" : "running it")};
      rows[n++] = {"delete ", sec.check_delete(abs, "deleting it")};
    } else {
      rows[n++] = {"create ", sec.check_create(abs, "creating it")};
    }
    for (int k = 0; k < n; ++k)
      printf("  %s %-7s  %s\n", rows[k].what, rows[k].d.ok ? "ALLOWED" : "DENIED", rows[k].d.why.c_str());
  }
  return 0;
}

int builtin_audit(Shell&, const Args& a) {
  if (!need_admin("audit")) return 1;
  size_t n = 20;
  if (a.size() == 2) n = (size_t)atoi(a[1].c_str());
  if (n == 0 || n > 10000) n = 20;
  for (const std::string& l : Security::get().audit_tail(n)) printf("%s\n", l.c_str());
  return 0;
}

static bool copy_file(const std::string& from, const std::string& to) {
  int in = open(from.c_str(), O_RDONLY);
  if (in < 0) return false;
  int out = open(to.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (out < 0) { close(in); return false; }
  char buf[8192];
  ssize_t k;
  bool ok = true;
  while ((k = read(in, buf, sizeof buf)) > 0)
    if (write(out, buf, (size_t)k) != k) { ok = false; break; }
  close(in);
  close(out);
  return ok && k == 0;
}

int builtin_cp(Shell&, const Args& a) {
  if (a.size() != 3) { fprintf(stderr, "cp: usage: cp SRC DST\n"); return 2; }
  Security& sec = Security::get();
  std::string src = a[1], dst = a[2];
  if (!exists(src)) { fprintf(stderr, "cp: cannot stat '%s': %s\n", src.c_str(), strerror(ENOENT)); return 1; }
  if (is_dir(src)) { fprintf(stderr, "cp: -r is not supported; '%s' is a directory\n", src.c_str()); return 1; }
  if (is_dir(dst)) dst += "/" + src.substr(src.rfind('/') + 1);
  bool existed = exists(dst);
  if (!sec.allow(sec.check(src, kRead, "copying it"), "cp", src)) return 1;
  if (!sec.allow(existed ? sec.check(dst, kWrite, "overwriting it") : sec.check_create(dst, "creating the copy"), "cp", dst))
    return 1;
  if (!copy_file(src, dst)) { fprintf(stderr, "cp: %s -> %s: %s\n", src.c_str(), dst.c_str(), strerror(errno)); return 1; }
  if (!existed) sec.record_new(dst, false);
  return 0;
}

int builtin_mv(Shell&, const Args& a) {
  if (a.size() != 3) { fprintf(stderr, "mv: usage: mv SRC DST\n"); return 2; }
  Security& sec = Security::get();
  std::string src = a[1], dst = a[2];
  if (!exists(src)) { fprintf(stderr, "mv: cannot stat '%s': %s\n", src.c_str(), strerror(ENOENT)); return 1; }
  if (is_dir(dst)) dst += "/" + src.substr(src.rfind('/') + 1);
  bool existed = exists(dst);
  if (!sec.allow(sec.check_delete(src, "moving it away"), "mv", src)) return 1;
  if (!sec.allow(existed ? sec.check_delete(dst, "replacing it") : sec.check_create(dst, "moving a file in"), "mv", dst))
    return 1;
  std::string from = sec.entry(src), to = sec.entry(dst);
  if (rename(src.c_str(), dst.c_str()) < 0) { fprintf(stderr, "mv: %s -> %s: %s\n", src.c_str(), dst.c_str(), strerror(errno)); return 1; }
  sec.moved(from, to);
  return 0;
}
