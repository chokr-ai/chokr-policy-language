---
title: Installation
description: Install the library and the cplang command, add the optional prover and check the installation.
---

The package provides the Python library `cplang` and the `cplang` command. This page covers every way to install it and what each one needs.

The language requires Python 3.12 or newer. Check your version before continuing:

```console
$ python --version
```

## Install with pip

```console
$ pip install chokr-policy-language
```

Install into a virtual environment when the policy tooling belongs to one project:

```console
$ python -m venv .venv
$ source .venv/bin/activate
$ pip install chokr-policy-language
```

## Install with uv

Add the package to a project:

```console
$ uv add chokr-policy-language
```

Or install only the command, isolated from every project:

```console
$ uv tool install chokr-policy-language
```

## Add the Prover

The prover answers questions such as "can this change allow something the old policy denied?" It needs an extra solver package, so it is an optional extra:

```console
$ pip install "chokr-policy-language[prove]"
```

Without the extra, every other command works as usual.

> Use the prover in CI when several people edit the same policy. See [Combining Rules](/decisions/) for how a policy reaches a verdict first.
{: .note}

## Verify the Installation

Print the version of the command:

```console
$ cplang --version
```

Then run the bundled conformance vectors. They exercise the whole language against the installed engine:

```console
$ cplang conformance
```

Expected output:

```console
136 passed, 0 failed
```

The command exits with `0` only when every vector passes.

## Install from Source

Clone the repository and let `uv` create the environment:

```console
$ git clone https://github.com/chokr-ai/chokr-policy-language
$ cd chokr-policy-language
$ uv sync
```

Run the command from the environment with `uv run cplang --help`.

## Editor Support

Policy and declaration files are plain YAML, and the language ships JSON Schemas for the documents it reads and writes. Print one with `cplang schema`:

```console
$ cplang schema
action
signal
verdict
fixtures
policy
```

Point your editor at `cplang schema policy` to get completion and structure checks while you type. The schema checks structure only. Expressions, types and names are checked by `cplang policy check`.

> ▶ Next: [Basics](/basics/)
{: .next}
