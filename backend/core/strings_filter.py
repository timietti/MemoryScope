# backend/core/strings_filter.py
"""
Server-side regex filter with AND / OR / NOT logical operators.

Grammar (EBNF)
--------------
  expr    := or_expr
  or_expr := and_expr  ( OR  and_expr  )*
  and_expr:= not_expr  ( AND not_expr  )*
  not_expr:= NOT not_expr | atom
  atom    := '(' expr ')' | regex_pattern

Operator precedence (tightest first): NOT > AND > OR
Keywords AND / OR / NOT are case-insensitive.
Each regex_pattern operand is matched case-insensitively via re.search().

Examples
--------
  cmd.exe AND powershell
  192\\.168 OR 10\\.0\\.0
  NOT explorer AND cmd.exe
  (cmd.exe OR powershell) AND NOT svchost
"""
from __future__ import annotations

import gzip
import io
import re
from typing import Callable

# ── Tokeniser ─────────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(
    r'\bAND\b|\bOR\b|\bNOT\b'  # keywords (whole-word)
    r'|\('                       # open paren
    r'|\)'                       # close paren
    r'|[^\s()]+',                # regex operand (anything else, no spaces/parens)
    re.IGNORECASE,
)


def _tokenise(expr: str) -> list[str]:
    return [m.group() for m in _TOKEN_RE.finditer(expr)]


# ── Recursive-descent parser ──────────────────────────────────────────────────

FilterFn = Callable[[str], bool]


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _consume(self, expected: str | None = None) -> str:
        tok = self._tokens[self._pos]
        if expected and tok.upper() != expected.upper():
            raise ValueError(f"Expected '{expected}', got '{tok}'")
        self._pos += 1
        return tok

    def parse(self) -> FilterFn:
        fn = self._or_expr()
        if self._pos < len(self._tokens):
            raise ValueError(f"Unexpected token '{self._tokens[self._pos]}'")
        return fn

    def _or_expr(self) -> FilterFn:
        left = self._and_expr()
        while self._peek() and self._peek().upper() == "OR":
            self._consume()
            right = self._and_expr()
            left = _or(left, right)
        return left

    def _and_expr(self) -> FilterFn:
        left = self._not_expr()
        while self._peek() and self._peek().upper() == "AND":
            self._consume()
            right = self._not_expr()
            left = _and(left, right)
        return left

    def _not_expr(self) -> FilterFn:
        if self._peek() and self._peek().upper() == "NOT":
            self._consume()
            operand = self._not_expr()
            return _not(operand)
        return self._atom()

    def _atom(self) -> FilterFn:
        tok = self._peek()
        if tok is None:
            raise ValueError("Unexpected end of filter expression")
        if tok.upper() in ("AND", "OR", "NOT"):
            raise ValueError(f"Expected a pattern or '(', got keyword '{tok}'")
        if tok == ")":
            raise ValueError("Unexpected ')'")
        if tok == "(":
            self._consume()
            fn = self._or_expr()
            closing = self._peek()
            if closing != ")":
                raise ValueError(f"Expected ')', got '{closing}'")
            self._consume()
            return fn
        # regex operand
        self._consume()
        try:
            pat = re.compile(tok, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid regex '{tok}': {exc}") from exc
        return lambda line, p=pat: bool(p.search(line))


def _and(a: FilterFn, b: FilterFn) -> FilterFn:
    return lambda line: a(line) and b(line)


def _or(a: FilterFn, b: FilterFn) -> FilterFn:
    return lambda line: a(line) or b(line)


def _not(a: FilterFn) -> FilterFn:
    return lambda line: not a(line)


# ── Public API ────────────────────────────────────────────────────────────────

def build_filter(expr: str) -> FilterFn | None:
    """
    Parse a logical filter expression and return a callable ``fn(line) -> bool``.
    Returns ``None`` if the expression is empty (caller should treat as match-all).
    Raises ``ValueError`` for syntax errors or invalid regexes.
    """
    expr = expr.strip()
    if not expr:
        return None
    tokens = _tokenise(expr)
    if not tokens:
        return None
    return _Parser(tokens).parse()


def search_strings(
    gz_data: bytes,
    filter_fn: FilterFn | None,
    page: int,
    page_size: int,
    max_matches: int,
) -> dict:
    """
    Stream-decompress *gz_data*, apply *filter_fn* to each line, and return
    one page of results.

    Parameters
    ----------
    gz_data:     raw bytes of the gzip-compressed strings file.
    filter_fn:   callable from build_filter(); None = match all.
    page:        1-based page number.
    page_size:   lines per page.
    max_matches: hard cap — scanning stops once this many matches are found.

    Returns
    -------
    {
        "total_matches": int,   # actual count or max_matches if capped
        "is_capped":    bool,   # True when max_matches was reached
        "page":         int,
        "page_size":    int,
        "results":      list[str],
    }
    """
    start = (page - 1) * page_size
    end = start + page_size

    matched_count = 0
    results: list[str] = []
    is_capped = False

    with gzip.GzipFile(fileobj=io.BytesIO(gz_data)) as gz:
        for raw in gz:
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if not line:
                continue
            # Lines are stored as "<offset> <string_part>".
            # Apply the filter to the string part only so that anchors like ^
            # and digit patterns don't accidentally match the offset prefix.
            space_idx = line.find(" ")
            string_part = line[space_idx + 1:] if space_idx >= 0 else line
            if filter_fn is None or filter_fn(string_part):
                matched_count += 1
                if matched_count > max_matches:
                    is_capped = True
                    # We've confirmed the cap — stop scanning
                    break
                if start < matched_count <= end:
                    results.append(line)  # return full line including offset

    return {
        "total_matches": max_matches if is_capped else matched_count,
        "is_capped": is_capped,
        "page": page,
        "page_size": page_size,
        "results": results,
    }
