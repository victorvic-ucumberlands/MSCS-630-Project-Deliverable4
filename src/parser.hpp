// parser.hpp - command-line lexer/parser.
//
// Grammar supported in Deliverable 1:
//
//   line     := command ( (';' | '&') command )* [ ';' | '&' ]
//   command  := word+ with optional redirections  <  >  >>  2>  2>>
//   word     := text with 'single quotes', "double quotes", \escapes,
//               $VAR ${VAR} $? $$ and a leading ~ expansion
//
// A trailing '&' runs that command in the background.  Pipes and && / ||
// are recognised but rejected with a clear message (later deliverables).
//
// The parser is *lazy*: Parser::next() lexes and expands one command at a time,
// so "false; echo $?" sees the status of `false`.  The shell therefore makes
// two passes over each line: a validation pass (so a syntax error anywhere in
// the line prevents *any* command from running) and an execution pass.
#pragma once

#include <functional>
#include <string>
#include <vector>

struct Redirect {
  enum class Kind { In, Out, Append };
  int fd;            // 0, 1 or 2 - which descriptor is redirected
  Kind kind;
  std::string path;
};

struct Command {
  std::vector<std::string> argv;   // expanded words; argv[0] is the command name
  std::vector<Redirect> redirs;
  bool background = false;         // terminated by '&'
  std::string text;                // original source text (used in job listings)
};

// Looks up a variable ("?" = last status, "$" = shell pid, else environment).
using VarLookup = std::function<std::string(const std::string&)>;

class Parser {
 public:
  enum class Status { Command, End, Error };

  static constexpr size_t kMaxLine = 4096;  // longest accepted input line
  static constexpr size_t kMaxArgs = 256;   // most words in one command

  Parser(const std::string& line, VarLookup lookup);

  // Produce the next command.  Returns Command / End (no more) / Error
  // (error() then holds a human-readable message).
  Status next(Command& out);
  const std::string& error() const { return error_; }

 private:
  enum class Tok { Word, Semi, Amp, In, Out, Append, Eof, Error };
  struct Token {
    Tok kind = Tok::Eof;
    std::string text;
    bool quoted = false;     // word contained quotes/escapes (so "" is a real argument)
    int fd = -1;             // redirect descriptor
    size_t begin = 0, end = 0;
  };

  Token lex();
  bool read_word(Token& t);
  bool expand_var(std::string& out);

  std::string line_;
  size_t pos_ = 0;
  VarLookup lookup_;
  std::string error_;
};
