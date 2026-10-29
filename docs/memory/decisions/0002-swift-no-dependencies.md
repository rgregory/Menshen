# ADR-002: Swift, no third-party dependencies

**Status**: Accepted

**Date**: 2026-10-29

## Context

Menshen is a security tool that runs other people's apps. Its own supply chain should be as small as possible, and it needs native access to code-signing information.

## Decision

Swift Package Manager, using only Foundation, Security.framework, Darwin (libproc), and Swift Testing. Arguments are parsed by hand, and configs use `Codable` JSON.

## Rationale

The user chose Swift. Security.framework (`SecStaticCode`) gives team ID, cdhash, entitlements, and Apple-anchor checks without shelling out to `codesign`. With zero dependencies nothing has to be fetched at build time, and there's nothing upstream to compromise.

## Consequences

The CLI parser is small and handwritten, and configs are JSON rather than TOML or YAML. Since JSON has no comments, each rule carries a `note` field.

## Alternatives Considered

- swift-argument-parser: nicer help output, but it's a network dependency.
- Python or Go: offered to the user, who declined.
