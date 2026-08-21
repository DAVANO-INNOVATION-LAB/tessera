# Security Policy

## Reporting a vulnerability

Please report security issues privately, not as a public GitHub issue.

Use [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, or email **security@davanoinnovation.com**.

Please include the affected version, what you observed, and — if you have one —
a file or command that reproduces it. We will acknowledge receipt, tell you
whether we can reproduce it, and keep you updated until a fix ships. Credit is
offered to reporters who want it.

## Scope

This project parses **untrusted binary model files**. The parsers are the part
most worth attacking, and the failures we care most about are:

- a crafted file that panics, hangs, or exhausts memory or CPU
- a crafted file that causes a read, write, or open outside the model directory
- a crafted file that suppresses a finding it should have produced — a silent
  clean verdict on a malicious artifact is as serious as a crash
- anything that lets the analyser reach the network

For Tessera Studio, add: anything reachable from a web page the user visits,
and anything that discloses paths or file contents outside the served directory.

## Non-goals

This is a supply-chain and artifact tool. It reports what a model file discloses
and how it can behave at load time. It does **not** evaluate model behaviour —
data poisoning, backdoor triggers, jailbreak robustness — because those require
training data and runtime observation that a static parse cannot see. Reports
that a model behaves badly at inference are out of scope here.

## Supported versions

The most recent release is supported. This project has not reached 1.0; until
then, fixes land on the latest version rather than being backported.
