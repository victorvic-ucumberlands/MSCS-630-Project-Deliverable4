// parser.cpp - lexer + parser implementation.  See parser.hpp for the grammar.
#include "parser.hpp"

#include <cctype>
#include <cstring>

Parser::Parser(const std::string& line, VarLookup lookup)
    : line_(line), lookup_(std::move(lookup)) {}

// Characters that end an unquoted word.
static bool is_delim(char c) {
  return c == ' ' || c == '\t' || c == ';' || c == '&' || c == '|' || c == '<' || c == '>';
}

// Handle a '$' at line_[pos_]: append the expansion to `out` and advance.
// Returns false (with error_ set) on malformed ${...}.
bool Parser::expand_var(std::string& out) {
  char n = pos_ + 1 < line_.size() ? line_[pos_ + 1] : '\0';
  if (n == '?' || n == '$') {                       // $? and $$
    out += lookup_(std::string(1, n));
    pos_ += 2;
  } else if (n == '{') {                            // ${NAME}
    size_t e = line_.find('}', pos_ + 2);
    if (e == std::string::npos || e == pos_ + 2) {
      error_ = "syntax error: bad substitution";
      return false;
    }
    std::string name = line_.substr(pos_ + 2, e - pos_ - 2);
    for (char c : name) {
      if (!(std::isalnum((unsigned char)c) || c == '_')) {
        error_ = "syntax error: bad substitution: ${" + name + "}";
        return false;
      }
    }
    out += lookup_(name);
    pos_ = e + 1;
  } else if (std::isalpha((unsigned char)n) || n == '_') {  // $NAME
    size_t e = pos_ + 1;
    while (e < line_.size() && (std::isalnum((unsigned char)line_[e]) || line_[e] == '_')) ++e;
    out += lookup_(line_.substr(pos_ + 1, e - pos_ - 1));
    pos_ = e;
  } else {                                          // lone '$' is literal
    out += '$';
    ++pos_;
  }
  return true;
}

// Read one word starting at pos_, handling quoting, escapes and expansion.
bool Parser::read_word(Token& t) {
  std::string w;
  size_t start = pos_;
  while (pos_ < line_.size()) {
    char c = line_[pos_];
    if (is_delim(c)) break;
    if (c == '\'') {                                // '...' : everything literal
      size_t e = line_.find('\'', pos_ + 1);
      if (e == std::string::npos) { error_ = "syntax error: unterminated single quote"; return false; }
      w.append(line_, pos_ + 1, e - pos_ - 1);
      pos_ = e + 1;
      t.quoted = true;
    } else if (c == '"') {                          // "..." : $ expands, \" \\ \$ escape
      ++pos_;
      bool closed = false;
      while (pos_ < line_.size()) {
        char d = line_[pos_];
        if (d == '"') { closed = true; ++pos_; break; }
        if (d == '\\' && pos_ + 1 < line_.size() && std::strchr("\"\\$", line_[pos_ + 1])) {
          w += line_[pos_ + 1];
          pos_ += 2;
        } else if (d == '$') {
          if (!expand_var(w)) return false;
        } else {
          w += d;
          ++pos_;
        }
      }
      if (!closed) { error_ = "syntax error: unterminated double quote"; return false; }
      t.quoted = true;
    } else if (c == '\\') {                         // \x : next char literal
      if (pos_ + 1 >= line_.size()) { error_ = "syntax error: trailing backslash"; return false; }
      w += line_[pos_ + 1];
      pos_ += 2;
      t.quoted = true;
    } else if (c == '$') {
      if (!expand_var(w)) return false;
    } else if (c == '~' && pos_ == start &&
               (pos_ + 1 >= line_.size() || line_[pos_ + 1] == '/' || is_delim(line_[pos_ + 1]))) {
      std::string home = lookup_("HOME");           // bare ~ or ~/path
      w += home.empty() ? "~" : home;
      ++pos_;
    } else {
      w += c;
      ++pos_;
    }
  }
  t.text = w;
  return true;
}

// Return the next token.  Unsupported operators set error_ and yield Tok::Error.
Parser::Token Parser::lex() {
  Token t;
  while (pos_ < line_.size() && (line_[pos_] == ' ' || line_[pos_] == '\t')) ++pos_;
  if (pos_ >= line_.size()) { t.kind = Tok::Eof; return t; }

  t.begin = pos_;
  char c = line_[pos_];
  char nx = pos_ + 1 < line_.size() ? line_[pos_ + 1] : '\0';

  if (c == '#') { pos_ = line_.size(); t.kind = Tok::Eof; return t; }  // comment

  switch (c) {
    case ';': ++pos_; t.kind = Tok::Semi; t.end = pos_; return t;
    case '&':
      if (nx == '&') { error_ = "'&&' is not supported yet"; t.kind = Tok::Error; return t; }
      ++pos_; t.kind = Tok::Amp; t.end = pos_; return t;
    case '|':
      error_ = (nx == '|') ? "'||' is not supported yet"
                           : "pipes ('|') are not supported yet (planned for a later deliverable)";
      t.kind = Tok::Error;
      return t;
    case '<': ++pos_; t.kind = Tok::In; t.fd = 0; t.end = pos_; return t;
    case '>':
      if (nx == '>') { pos_ += 2; t.kind = Tok::Append; } else { ++pos_; t.kind = Tok::Out; }
      t.fd = 1;
      t.end = pos_;
      return t;
  }

  if (!read_word(t)) { t.kind = Tok::Error; return t; }
  t.kind = Tok::Word;
  t.end = pos_;

  // "2>" / "2>>": a lone unquoted 2 glued to '>' selects stderr.
  if (t.text == "2" && !t.quoted && pos_ < line_.size() && line_[pos_] == '>') {
    Token r = lex();
    if (r.kind == Tok::Out || r.kind == Tok::Append) { r.fd = 2; r.begin = t.begin; return r; }
    return r;
  }
  return t;
}

Parser::Status Parser::next(Command& out) {
  out = Command{};
  size_t first = std::string::npos, last = 0;   // source span of this command

  auto finish = [&]() -> Status {
    if (out.argv.empty()) { error_ = "syntax error: missing command name"; return Status::Error; }
    out.text = line_.substr(first, last - first);
    return Status::Command;
  };
  auto note = [&](const Token& t) {
    if (first == std::string::npos) first = t.begin;
    last = t.end;
  };

  for (;;) {
    Token t = lex();
    switch (t.kind) {
      case Tok::Error:
        return Status::Error;

      case Tok::Word:
        if (!t.quoted && t.text.empty()) continue;   // unquoted empty expansion vanishes
        if (out.argv.size() >= kMaxArgs) {
          error_ = "too many arguments (limit " + std::to_string(kMaxArgs) + ")";
          return Status::Error;
        }
        out.argv.push_back(t.text);
        note(t);
        break;

      case Tok::In: case Tok::Out: case Tok::Append: {
        note(t);
        Token f = lex();
        if (f.kind == Tok::Error) return Status::Error;
        if (f.kind != Tok::Word || (f.text.empty() && !f.quoted)) {
          error_ = "syntax error: expected a file name after redirection operator";
          return Status::Error;
        }
        note(f);
        Redirect r;
        r.fd = t.fd;
        r.kind = t.kind == Tok::In ? Redirect::Kind::In
               : t.kind == Tok::Out ? Redirect::Kind::Out : Redirect::Kind::Append;
        r.path = f.text;
        out.redirs.push_back(r);
        break;
      }

      case Tok::Semi: case Tok::Amp:
        if (out.argv.empty() && out.redirs.empty()) {
          error_ = std::string("syntax error near unexpected token '") +
                   (t.kind == Tok::Semi ? ";" : "&") + "'";
          return Status::Error;
        }
        out.background = (t.kind == Tok::Amp);
        return finish();

      case Tok::Eof:
        if (out.argv.empty() && out.redirs.empty()) return Status::End;
        return finish();
    }
  }
}
