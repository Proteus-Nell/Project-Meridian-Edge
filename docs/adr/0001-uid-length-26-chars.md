# ADR 0001: UID is 26 Crockford Base32 characters

**Status:** accepted · **Date:** 2026-07-04

## Context

MVP_DOC.md §6.1 and CLAUDE.md §2.1 both specify a 128-bit (16-byte) CSPRNG UID
encoded as Crockford Base32 and state "26 characters", but the grouping example
given (`XXXX-XXXX-XXXX-XXXX-XXXX-XX`, e.g. `7Q3K-M2VD-9XWP-4RTB-A6HJ-EZ`) is
only 22 characters, which would encode just 110 bits.

## Decision

The 128-bit requirement is authoritative: ⌈128 / 5⌉ = **26 characters**,
displayed grouped as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX` (6×4 + 2). Parsers
accept UIDs with or without dashes, case-insensitively, with standard Crockford
ambiguity mapping (I/L→1, O→0).

## Consequences

The doc examples are superseded by this ADR. Client and server both validate
against 26 canonical characters (`UID_CHARS` in the shared constants files).
