# OSIRIS Intel Wrapper

Canonical, git-tracked copy of the local read-only OSIRIS wrapper used by
Hermes Telegram commands.

Deployed path:

```bash
/root/scripts/osiris_intel/osiris_intel.py
```

When changing this wrapper, edit the tracked copy in this directory first, run:

```bash
python3 -m unittest scripts/osiris_intel/tests/test_osiris_intel.py
```

Then sync the deployed copy:

```bash
cp scripts/osiris_intel/osiris_intel.py /root/scripts/osiris_intel/osiris_intel.py
cp scripts/osiris_intel/tests/test_osiris_intel.py /root/scripts/osiris_intel/tests/test_osiris_intel.py
```

The wrapper is intentionally read-only: no wallet, trading, posting, cron, or
AIBTC write actions.
