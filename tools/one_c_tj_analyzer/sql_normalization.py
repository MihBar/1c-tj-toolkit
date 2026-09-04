"""Versioned PostgreSQL SQL token signatures, independent of display samples.

This is a lexical signature, not an optimizer or a SQL equivalence prover.
Unknown/ambiguous lexical input is retained verbatim in an explicit raw form.
Only relation names in the documented 1C temporary namespace are alpha-renamed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

SQL_NORMALIZATION_VERSION = "2.0"
LEGACY_SQL_NORMALIZATION_VERSION = "1.0-regex"
SQL_FINGERPRINT_ALGORITHM = "sha256:1c-tj-sql-nul-version-nul-text:utf8"
RAW_PREFIX = "<raw-sql> "
SQL_CSV_FIELDS = ["sql_normalization_version", "sql_normalization_status"]

_NUMBER = re.compile(r"(?:0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+|"
                     r"(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9][0-9_]*)?)")
_DOLLAR = re.compile(r"\$(?:[^\W\d][\w]*|_[\w]*)?\$", re.UNICODE)
_TEMP = re.compile(r"tt[0-9]+\Z")
_TEMP_SCHEMA = re.compile(r"pg_temp(?:_[0-9]+)?\Z")
_OPERATORS = set("+-*/<>=~!@#%^&|`?")
_SPECIAL_OPERATORS = set("~!@#%^&|`?")
_CLAUSE_END = set("where group order having limit offset fetch returning union intersect except window set values".split())
_NOT_ALIAS = _CLAUSE_END | set("on join left right full inner outer cross natural using tablesample for as with to cascade restrict".split())
_TYPE_MODIFIERS = set("numeric decimal varchar char character bit varbit time timestamp interval float".split())


class LexicalError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    newline_before: bool = False

    @property
    def name(self) -> str | None:
        if self.kind == "word":
            return self.text.lower()
        if self.kind == "identifier":
            return self.text[1:-1].replace('""', '"')
        return None

    @property
    def keyword(self) -> str:
        return self.text.lower() if self.kind == "word" else ""


def _quoted_end(sql: str, start: int, quote: str, escapes: bool) -> int:
    i = start + 1
    while i < len(sql):
        if escapes and sql[i] == "\\":
            i += 2
        elif sql[i] == quote:
            if i + 1 < len(sql) and sql[i + 1] == quote:
                i += 2
            else:
                return i + 1
        else:
            i += 1
    raise LexicalError("Unterminated quoted token")


def tokenize(sql: str) -> list[Token]:
    tokens: list[Token] = []
    i, newline = 0, False
    while i < len(sql):
        start, ch = i, sql[i]
        if ch.isspace():
            newline |= ch in "\r\n"
            i += 1
            continue
        if sql.startswith("--", i):
            i += 2
            while i < len(sql) and sql[i] not in "\r\n":
                i += 1
            continue
        if sql.startswith("/*", i):
            depth, i = 1, i + 2
            while i < len(sql) and depth:
                if sql.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif sql.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    newline |= sql[i] in "\r\n"
                    i += 1
            if depth:
                raise LexicalError("Unterminated comment")
            continue
        # Unicode-escaped identifiers can use a later UESCAPE clause. Preserve
        # the entire statement rather than guessing their resolved identity.
        if sql[i:i+3].lower() == 'u&"':
            raise LexicalError("Unicode-escaped identifier")
        prefix = ""
        quote_at = i
        if sql[i:i+3].lower() == "u&'":
            prefix, quote_at = "u&", i + 2
        elif ch.lower() in "ebxn" and sql[i+1:i+2] == "'":
            prefix, quote_at = ch.lower(), i + 1
        if sql[quote_at:quote_at+1] == "'":
            # A plain continuation of an E string inherits escape processing.
            continuation = not prefix and newline and tokens and tokens[-1].kind.startswith("string:")
            previous_prefix = tokens[-1].kind.partition(":")[2] if continuation else ""
            effective_prefix = prefix or previous_prefix
            i = _quoted_end(sql, quote_at, "'", effective_prefix == "e")
            raw = sql[start:i]
            if not effective_prefix and "\\" in raw:
                raise LexicalError("Plain backslash string depends on server settings")
            if continuation:
                previous = tokens.pop()
                tokens.append(Token(previous.kind, previous.text + "\n" + raw, previous.newline_before))
                newline = False
                continue
            kind = "string:" + prefix
        elif ch == '"':
            i = _quoted_end(sql, i, '"', False)
            kind = "identifier"
        elif ch == "$" and (match := _DOLLAR.match(sql, i)):
            tag = match.group()
            end = sql.find(tag, match.end())
            if end < 0:
                raise LexicalError("Unterminated dollar string")
            i, kind = end + len(tag), "dollar_string"
        elif ch == "$" and i + 1 < len(sql) and sql[i+1].isascii() and sql[i+1].isdigit():
            i += 2
            while i < len(sql) and sql[i].isascii() and sql[i].isdigit():
                i += 1
            kind = "parameter"
        elif ch == "_" or ch.isalpha() or ord(ch) >= 128:
            i += 1
            while i < len(sql) and (sql[i].isalnum() or sql[i] in "_$" or ord(sql[i]) >= 128):
                i += 1
            kind = "word"
        elif match := _NUMBER.match(sql, i):
            i, kind = match.end(), "number"
        elif sql[i:i+2] in {"::", ":=", ".."}:
            i, kind = i + 2, "punctuation"
        elif ch in _OPERATORS:
            i += 1
            while i < len(sql) and sql[i] in _OPERATORS and not sql.startswith(("--", "/*"), i):
                i += 1
            if not set(sql[start:i]) & _SPECIAL_OPERATORS:
                while i > start + 1 and sql[i-1] in "+-":
                    i -= 1
            kind = "operator"
        elif ch in "(),.;:[]":
            i, kind = i + 1, "punctuation"
        else:
            raise LexicalError("Unknown SQL character")
        tokens.append(Token(kind, sql[start:i], newline))
        newline = False
    return tokens


def _scopes(tokens: list[Token]):
    scopes, parents, closing = [], {0: None}, {}
    stack, scope = [], 0
    for i, token in enumerate(tokens):
        if token.text in {")", "]"}:
            if not stack:
                raise LexicalError("Unbalanced parentheses")
            opening, scope = stack.pop()
            if tokens[opening].text != {")": "(", "]": "["}[token.text]:
                raise LexicalError("Mismatched brackets")
            closing[opening] = i
        scopes.append(scope)
        if token.text in {"(", "["}:
            stack.append((i, scope))
            child = len(parents)
            parents[child], scope = scope, child
        elif token.text == ";" and not stack:
            scope = len(parents)
            parents[scope] = None
    if stack:
        raise LexicalError("Unbalanced parentheses")
    return scopes, parents, closing


def _name_at(tokens: list[Token], i: int) -> tuple[tuple[str, ...], int]:
    if i >= len(tokens) or tokens[i].name is None:
        return (), i
    names = [tokens[i].name]
    i += 1
    while i + 1 < len(tokens) and tokens[i].text == "." and tokens[i+1].name is not None:
        names.append(tokens[i+1].name)
        i += 2
    return tuple(names), i


def _relations(tokens: list[Token]):
    scopes, parents, closing = _scopes(tokens)
    bindings: dict[int, dict[str, tuple | None]] = {s: {} for s in parents}
    ctes: dict[int, set[str]] = {s: set() for s in parents}
    by_scope: dict[int, list[int]] = {s: [] for s in parents}
    for i, s in enumerate(scopes):
        by_scope[s].append(i)
    # CTE names are physical query structure, including names that resemble ttN.
    for scope, indices in by_scope.items():
        if not indices or tokens[indices[0]].keyword != "with":
            continue
        i = indices[0] + 1
        if tokens[i].keyword == "recursive":
            i += 1
        while i < len(tokens):
            name, end = _name_at(tokens, i)
            if len(name) != 1:
                break
            ctes[scope].add(name[0])
            if end < len(tokens) and tokens[end].text == "(":
                end = closing[end] + 1
            if end >= len(tokens) or tokens[end].keyword != "as":
                break
            end += 1
            while end < len(tokens) and tokens[end].keyword in {"not", "materialized"}:
                end += 1
            if end >= len(tokens) or tokens[end].text != "(":
                break
            i = closing[end] + 1
            if i >= len(tokens) or tokens[i].text != ",":
                break
            i += 1

    def is_cte(scope: int, name: str) -> bool:
        while scope is not None:
            if name in ctes[scope]:
                return True
            scope = parents[scope]
        return False

    replacements, relation_names, relation_ranges = {}, [], {}
    declared: dict[str, int] = {}
    relation_group_scopes: set[int] = set()
    for scope, indices in by_scope.items():
        words = {tokens[i].keyword for i in indices}
        if scope not in relation_group_scopes and not words & {"select", "update", "insert", "delete", "create", "drop", "alter", "truncate", "analyze", "table"}:
            continue
        expect, in_from, consumed, function_allowed = False, False, -1, False
        if scope in relation_group_scopes:
            expect, in_from, function_allowed = True, True, True
        declare_target = False
        for i in indices:
            if i < consumed:
                continue
            token, word = tokens[i], tokens[i].keyword
            if expect:
                if word in {"only", "lateral", "if", "not", "exists"}:
                    continue
                expect = False
                names, end = _name_at(tokens, i)
                relation_group = None
                if not names:
                    # A derived table's alias must shadow outer relation names.
                    if token.text == "(":
                        end = closing[i] + 1
                        if i+1 < end-1 and tokens[i+1].keyword not in {"select", "with", "values", "table"}:
                            relation_group = scopes[i+1]
                            relation_group_scopes.add(relation_group)
                    else:
                        continue
                function = bool(names and end < len(tokens) and tokens[end].text == "(" and function_allowed)
                if function:
                    end = closing[end] + 1
                temp = None
                if names and not function:
                    relation_ranges[i] = end
                    relation_names.append("".join(t.text for t in tokens[i:end]))
                    if declare_target:
                        declared.setdefault(names[-1], i)
                    if len(names) == 2 and _TEMP_SCHEMA.fullmatch(names[0]):
                        temp = names
                    elif len(names) == 1 and not is_cte(scope, names[0]) and (
                            _TEMP.fullmatch(names[0]) or declared.get(names[0], len(tokens)) <= i):
                        temp = ("pg_temp", names[0])
                    if temp:
                        replacements[i] = (end, temp)
                alias_at = end
                if alias_at < len(tokens) and tokens[alias_at].keyword == "as":
                    alias_at += 1
                alias = (tokens[alias_at].name if alias_at < len(tokens) and
                         tokens[alias_at].name is not None and tokens[alias_at].keyword not in _NOT_ALIAS else None)
                if alias is not None:
                    if alias in bindings[scope] and bindings[scope][alias] is not None:
                        raise LexicalError("Ambiguous relation binding")
                    bindings[scope][alias] = None
                    consumed = alias_at + 1
                else:
                    if relation_group is not None:
                        # Parenthesized joins/ONLY without an alias expose the
                        # enclosed relation bindings to the containing SELECT.
                        bindings[relation_group] = bindings[scope]
                    if names:
                        if names[-1] in bindings[scope] and bindings[scope][names[-1]] != temp:
                            raise LexicalError("Ambiguous relation binding")
                        bindings[scope][names[-1]] = temp
                    consumed = end
                declare_target = False
                continue
            if word in _CLAUSE_END | {"select"}:
                in_from = False
            if word in {"from", "join", "update", "into"}:
                expect = True
                function_allowed = word in {"from", "join"}
                if word in {"from", "join"}:
                    in_from = True
            elif word == "using" and "delete" in words:
                expect, in_from, function_allowed = True, True, False
            elif word in {"table", "truncate", "analyze"} and words & {"create", "drop", "alter", "truncate", "analyze", "table"}:
                expect, in_from, function_allowed = True, True, False
                declare_target = word == "table" and "create" in words and bool(words & {"temp", "temporary"})
            elif word == "on" and "create" in words and "index" in words:
                expect, function_allowed = True, False
            elif token.text == "," and in_from:
                expect = True

    # Resolve qualifiers after seeing FROM, since SELECT usually occurs first.
    known_temps = {identity for _, identity in replacements.values()}
    i = 0
    while i < len(tokens):
        if i in relation_ranges:
            i = relation_ranges[i]
            continue
        names, end = _name_at(tokens, i)
        star = end + 1 < len(tokens) and tokens[end].text == "." and tokens[end+1].text == "*"
        if (len(names) >= 3 or len(names) == 2 and star) and names[:2] in known_temps:
            replacements[i] = (i + 3, names[:2])
        elif len(names) >= 2 or len(names) == 1 and star:
            scope = scopes[i]
            while scope is not None:
                if names[0] in bindings[scope] or names[0] in ctes[scope]:
                    temp = bindings[scope].get(names[0])
                    if temp:
                        replacements[i] = (i + 1, temp)
                    break
                scope = parents[scope]
        i = max(i + 1, end)
    return replacements, relation_names, scopes


def normalize_sql(sql: str) -> str:
    try:
        tokens = tokenize(sql)
        replacements, _, scopes = _relations(tokens)
        identities: dict[tuple, int] = {}
        result, i = [], 0
        ordinal_scope: dict[int, bool] = {}
        type_modifier_scopes = {scopes[j+1] for j, t in enumerate(tokens[:-1]) if t.text == "(" and
                                j and tokens[j-1].name in _TYPE_MODIFIERS}
        while i < len(tokens):
            token, scope = tokens[i], scopes[i]
            if i in replacements:
                end, identity = replacements[i]
                index = identities.setdefault(identity, len(identities) + 1)
                result.append(f"<temp:{index}>")
                i = end
                continue
            # ORDER/GROUP BY ordinals refer to output fields, not literal data.
            if token.keyword == "by" and i and tokens[i-1].keyword in {"order", "group"}:
                ordinal_scope[scope] = True
            elif token.keyword in _CLAUSE_END - {"order", "group"} or token.text == ";":
                ordinal_scope[scope] = False
            if token.text == "(" and ordinal_scope.get(scope) and i and i+1 < len(tokens) and tokens[i-1].text.lower() in {"by", ",", "("}:
                ordinal_scope[scopes[i+1]] = True
            if token.kind == "word":
                value = token.text.lower()
            elif token.kind == "number":
                positional = ordinal_scope.get(scope) and i and tokens[i-1].text.lower() in {"by", ",", "("} and (
                    i + 1 == len(tokens) or tokens[i+1].text in {",", ")", ";"} or
                    tokens[i+1].keyword in _CLAUSE_END | {"asc", "desc", "nulls"})
                value = token.text if positional or scope in type_modifier_scopes else "<number>"
            elif token.kind.startswith("string:") or token.kind == "dollar_string":
                prefix = token.kind.partition(":")[2]
                value = "<bits>" if prefix in {"b", "x"} else "<string>"
                if i and tokens[i-1].keyword == "uescape":
                    value = token.text
            else:
                value = token.text
            result.append(value)
            i += 1
        return " ".join(result)
    except (LexicalError, IndexError):
        return RAW_PREFIX + json.dumps(sql, ensure_ascii=False)


def normalization_status(normalized_sql: str) -> str:
    return "raw_fallback" if normalized_sql.startswith(RAW_PREFIX) else "normalized"


def sql_fingerprint(normalized_sql: str, version: str = SQL_NORMALIZATION_VERSION) -> str:
    if version == LEGACY_SQL_NORMALIZATION_VERSION:
        payload = normalized_sql
    elif version == SQL_NORMALIZATION_VERSION:
        payload = "1c-tj-sql\0" + version + "\0" + normalized_sql
    else:
        raise ValueError(f"Unsupported SQL normalization version: {version}")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sql_tables(sql: str) -> list[str]:
    try:
        return _relations(tokenize(sql))[1]
    except (LexicalError, IndexError):
        return []


def sql_features(normalized_sql: str) -> dict[str, bool | None]:
    names = "join case distinct order_by group_by union temp_table limit_or_top".split()
    if normalization_status(normalized_sql) == "raw_fallback":
        return {"has_" + name: None for name in names}
    tokens = tokenize(normalized_sql)
    words = [t.keyword for t in tokens]
    pairs = set(zip(words, words[1:]))
    result = {"has_" + name: name in words for name in ("join", "case", "distinct", "union")}
    result.update(has_order_by=("order", "by") in pairs, has_group_by=("group", "by") in pairs,
                  has_limit_or_top=bool({"limit", "top"} & set(words)),
                  has_temp_table=any(t.text == "temp" and i and tokens[i-1].text == "<" and
                                     i+1 < len(tokens) and tokens[i+1].text == ":" for i, t in enumerate(tokens)))
    return result
