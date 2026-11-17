# Contributing

Thank you for helping make refrigeration controllers safer.

## Ground rules

- Code, comments, file names and commit messages are in English. User-facing
  text lives in `coldperimeter/report/locales/`; every key must exist in every
  language file (a test checks this).
- The tool stays read-only. Pull requests that try passwords, write to
  devices or change router settings will not be accepted.
- Never commit customer data. `out/` and `captures/` are git-ignored; keep it
  that way.

## Development setup

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e '.[dev]'
.venv/bin/python -m pytest
```

Try the interface against simulated devices:

```bash
.venv/bin/python -m tests.simulators.servers
```

```bash
.venv/bin/coldperimeter ui --browser
```

Then use targets `127.0.0.1`, ports `http:18080,modbus:15020` and router
address `http://127.0.0.1:15000/desc.xml` under "Advanced options".

## Adding a controller signature

Signatures are YAML files in `coldperimeter/fingerprint/signatures/`. Each
entry has a weight and a `status`: `documented` (vendor documentation or an
official advisory) or `unverified`.

1. Capture the device on a network you are authorized to audit, with
   sanitizing switched on:

   ```bash
   coldperimeter capture --targets 192.168.10.20 --sanitize --site "Lab" --authorized-by "Me" --operator "Me"
   ```

2. Read the capture file and remove anything that still identifies the site.
   Sanitizing removes store names, IP addresses and the device part of MAC
   addresses, but page bodies can contain other details.
3. Add or refine the signature, add the sanitized capture under
   `tests/fixtures/`, and add a test that identifies it.
4. Say in the pull request which model and firmware the capture comes from.

## Interface

The interface in `coldperimeter/gui/static/` is plain HTML, CSS and
JavaScript with no build step and no external resources. Keep it that way:
the app must work offline and load nothing from third parties.
