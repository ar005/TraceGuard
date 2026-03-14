# Deploy admin portal
cd edr-admin
pip install -r requirements.txt

# Reset
python app.py --force-setup
```

Output will now look like:
```
──────────────────────────────────────────────────────
  --force-setup: delete ALL users via direct DB connection
  DB: edr@localhost:5432/edr
──────────────────────────────────────────────────────
  1 user(s) will be permanently deleted.

  Found 1 user(s):
    • admin                  role=admin

  Type  yes  to confirm: yes
  Deleting… ✓  1 user(s) deleted.
  Open http://localhost:5001 — setup page will appear.