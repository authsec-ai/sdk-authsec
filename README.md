# AuthSec SDK Monorepo

AuthSec SDK provides enterprise authentication, authorization, service access, delegated trust, CIBA, and SPIFFE helpers for Python and TypeScript.

This repository is a monorepo. The root README is the landing page. Language-specific usage lives in the package READMEs.

## Packages

| Package | Language | Install | Docs |
| --- | --- | --- | --- |
| `authsec-sdk` | Python | `python3 -m pip install authsec-sdk` | [`packages/python-sdk/README.md`](packages/python-sdk/README.md) |
| `@authsec/sdk` | TypeScript / JavaScript | `npm install @authsec/sdk` | [`packages/typescript-sdk/README.md`](packages/typescript-sdk/README.md) |

## Capability Matrix

| Capability | Python | TypeScript |
| --- | --- | --- |
| MCP OAuth + RBAC enforcement | Yes | Yes |
| Public MCP tool registration | Yes | Yes |
| Hosted service credential access | Yes | Yes |
| Trust delegation for AI agents | Yes | Yes |
| CIBA / passwordless auth | Yes | Yes |
| SPIFFE / workload identity | Yes | Yes |

## Start Here

- Building or securing a Python MCP server:
  Use [`packages/python-sdk/README.md`](packages/python-sdk/README.md)
- Building or securing a TypeScript MCP server:
  Use [`packages/typescript-sdk/README.md`](packages/typescript-sdk/README.md)
- Building an agent that uses delegated trust:
  Read the trust delegation section in the package README for your language

## Install

Python:

```bash
python3 -m pip install -U authsec-sdk
```

TypeScript:

```bash
npm install @authsec/sdk
```

From this monorepo:

Python editable install:

```bash
python3 -m pip install -e packages/python-sdk
```

TypeScript local build:

```bash
cd packages/typescript-sdk
npm install
npm run build
```

## Repository Layout

- [`packages/python-sdk`](packages/python-sdk): published Python package
- [`packages/typescript-sdk`](packages/typescript-sdk): published TypeScript package

## Contributor Workflow

1. Make SDK changes in the relevant package.
2. Keep the root README short and package-neutral.
3. Keep the Python and TypeScript package READMEs authoritative for code samples and environment variables.
4. When a feature exists in one SDK and should exist in the other, update the capability matrix and both package READMEs together.

## Release Workflow

Python:

```bash
cd packages/python-sdk
python3 -m pip install --upgrade build twine
python3 -m build
python3 -m twine check dist/*
python3 -m twine upload dist/*
```

TypeScript:

```bash
cd packages/typescript-sdk
npm install
npm run clean
npm run build
npm pack
npm publish --access public
```

## Notes

- The `origin/stable` branch is a regression reference only.
- Package READMEs should describe real published capabilities, not aspirational ones.
- App-specific dependencies such as `openai` belong in the consuming application, not in these SDK packages.
