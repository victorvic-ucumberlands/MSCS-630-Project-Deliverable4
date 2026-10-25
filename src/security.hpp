// security.hpp - user authentication and file permissions (Deliverable 4).
//
// Authentication
//   Users live in $MYSHELL_HOME/passwd, one line per user:
//       name:role:iterations:salt:hash:failures:locked:last_login
//   The password itself is never stored, only PBKDF2-HMAC-SHA256 of it with a
//   per-user random salt (crypto.hpp).  Three roles:
//       admin     administrator: may read and write every file, manage users,
//                 and change system settings (scheduler, memory, semaphores)
//       standard  an ordinary user, limited by the permission bits
//       guest     read-only: may never write, create or delete anything
//   Five wrong passwords in a row lock the account until an admin unlocks it.
//   Every login, failure, lock and denied operation is written to
//   $MYSHELL_HOME/audit.log.
//
// File permissions
//   The managed file system is the directory tree $MYSHELL_FS (default: fs/
//   next to the shell).  Every file and directory in it has an owner, a group
//   and Unix-style mode bits (rwx for owner, group, others, plus the sticky
//   bit), kept by the shell in $MYSHELL_HOME/fsmeta.  A user's group is the
//   group of their role: admin, users or guest.  The shell is the reference
//   monitor: before every protected operation it asks check_*(), which applies
//       1. role rules: admin may read/write anything (execute needs an x bit,
//          as for root); a guest may never modify anything;
//       2. traversal: every directory on the way needs x (search) permission;
//       3. the owner / group / other bits of the target (or, to create or
//          delete, of its directory - and the sticky bit: in a sticky
//          directory only a file's owner may delete or rename it);
//   and returns the decision with the rule that produced it.
//   Outside the managed tree the real Unix permissions apply, and only admin
//   may modify files there.  The security database itself ($MYSHELL_HOME) is
//   reachable only through the user-management commands.
#pragma once

#include <sys/types.h>

#include <map>
#include <string>
#include <vector>

enum class Role { Admin, Standard, Guest };
const char* to_string(Role r);
bool parse_role(const std::string& s, Role& out);
std::string group_of(Role r);              // admin / users / guest

struct User {
  std::string name;
  Role role = Role::Standard;
  unsigned iterations = 0;
  std::string salt, hash;                  // hex
  int failures = 0;                        // consecutive failed logins
  bool locked = false;
  long last_login = 0;                     // time_t
};

struct FileMeta {
  std::string owner, group;
  unsigned mode = 0644;                    // includes 01000 = sticky
  bool recorded = false;                   // false = derived from the directory above
};

enum Perm { kRead = 4, kWrite = 2, kExec = 1 };

struct Decision {
  bool ok = true;
  std::string why;                         // the rule that decided it (for messages and the audit log)
};

class Security {
 public:
  static Security& get();                  // one per shell process

  // ---- set-up ------------------------------------------------------------
  std::string init();                      // locate the database and the managed tree ("" = ok)
  std::string setup_demo();                // create demo users and the demo file tree
  const std::string& home_dir() const { return home_; }
  const std::string& fs_root() const { return fs_; }
  bool have_users() const { return !users_.empty(); }

  // ---- authentication ----------------------------------------------------
  enum class Auth { Ok, Bad, Locked, NoSuchUser };
  Auth authenticate(const std::string& name, const std::string& password);
  void begin_session(const std::string& name);
  void end_session();
  const User* current() const;
  bool logged_in() const { return !session_.empty(); }
  bool is_admin() const { const User* u = current(); return u && u->role == Role::Admin; }
  std::string user() const { return session_; }
  std::string home_of(const std::string& name) const;   // fs/home/<name>
  int failures_before_login = 0;           // shown in the welcome message
  long previous_login = 0;

  // ---- user management (admin) -------------------------------------------
  const std::map<std::string, User>& users() const { return users_; }
  std::string add_user(const std::string& name, Role role, const std::string& password);
  std::string del_user(const std::string& name);
  std::string set_password(const std::string& name, const std::string& password);
  std::string set_role(const std::string& name, Role role);
  std::string unlock(const std::string& name);
  static std::string password_problem(const std::string& pw);   // "" = acceptable

  // ---- file permissions ---------------------------------------------------
  std::string canon(const std::string& path) const;    // absolute, symlinks of existing parts resolved
  std::string entry(const std::string& path) const;    // like canon, but a final symlink is not followed
  bool managed(const std::string& abs) const;           // inside the managed tree
  bool in_db(const std::string& abs) const;             // inside the security database
  FileMeta meta(const std::string& abs);                 // recorded or derived
  Decision check(const std::string& path, int perms, const std::string& op);  // existing path
  Decision check_create(const std::string& path, const std::string& op);      // a new entry
  Decision check_delete(const std::string& path, const std::string& op);      // unlink / rmdir / rename source
  Decision check_chmod(const std::string& path);
  Decision check_chown(const std::string& path);
  Decision require_admin(const std::string& op);         // non-file system settings
  void record_new(const std::string& path, bool dir);    // owner = current user, mode from defaults
  void set_meta(const std::string& path, const std::string& owner, const std::string& group, unsigned mode);
  void forget(const std::string& path);
  void moved(const std::string& from, const std::string& to);
  std::string rel(const std::string& abs) const;         // for messages: fs/..., or the path
  static std::string mode_string(unsigned mode, bool dir);
  static bool parse_mode(const std::string& spec, unsigned old, bool dir, unsigned& out);

  // Report a decision: prints "op: path: Permission denied (rule)" and audits a denial.
  bool allow(const Decision& d, const char* cmd, const std::string& path);

  // ---- audit log --------------------------------------------------------------
  void audit(const std::string& event);
  std::vector<std::string> audit_tail(size_t n) const;

 private:
  void load_users();
  void save_users();
  void load_meta();
  void refresh_meta();                      // re-read the journal if another process appended
  void append_meta(const std::string& line);
  Decision bits(const std::string& abs, int perms, const std::string& what);   // owner/group/other
  Decision traverse(const std::string& abs);                                   // x on every directory

  std::string home_, fs_, passwd_path_, meta_path_, audit_path_;
  std::map<std::string, User> users_;
  std::map<std::string, FileMeta> meta_;   // key: path relative to fs_ ("" = the root)
  long meta_size_ = -1;
  std::string session_;
};
