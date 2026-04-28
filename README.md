# SQLens 🔍

> A secure, elegant, single-file SQLite database viewer built in PHP.

Drop one file on any PHP server. Upload a `.sqlite` database. Explore it instantly — no install, no config, no dependencies.

![PHP](https://img.shields.io/badge/PHP-8.0+-777BB4?style=flat-square&logo=php&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Size](https://img.shields.io/badge/size-single%20file-orange?style=flat-square)

---

## Features

### 🗄️ Database Browsing
- Sidebar lists all tables and views with live row counts
- Sortable columns (click header to toggle asc/desc)
- Per-table row filter with debounce
- Adjustable page size (25 / 50 / 100 / 250 / 500 rows)
- Smooth paginator with page-jump input
- Long cell values truncate inline and expand in a modal on click
- Table schema viewer (raw `CREATE TABLE` SQL + indexes)

### 🔍 Universal Search
- Searches across every table simultaneously
- Results grouped by table with match highlighting
- Blob and re-encoded cells handled gracefully in results
- Debounced — no query fires while you're still typing

### 📦 Blob Handling
- Binary columns detected automatically via null-byte sniffing
- Hex preview shown inline (`A1 B2 C3 D4…`)
- MIME type detected via `finfo`
- **↓ Download** button per cell — serves the raw blob with the correct `Content-Type` and a sensible filename (`blob_table_column_rowid.png` etc.)

### 🌐 Encoding Safety
- Every cell value checked for valid UTF-8 before rendering
- Auto re-encoding attempted: `Windows-1252`, `ISO-8859-1`, `ISO-8859-15`, `Shift-JIS`, `EUC-JP`, `GB18030`
- Re-encoded cells display with a source-encoding badge (e.g., `Windows-1252`)
- Unconvertible binary data falls back to blob handling — nothing is garbled or silently dropped

### 📤 Export
| Format | Table view | Search results |
|--------|-----------|----------------|
| CSV    | ✅ with active filter | ✅ all matching tables |
| PDF    | ✅ landscape A4, styled | ✅ one page per table |

CSV exports include a UTF-8 BOM so Excel opens them correctly. Blobs render as `[BLOB 4.2KB]` in exports.

### 📊 Nerd Stats Panel
- SQLite version, page size, page count, free pages
- Encoding, journal mode, auto-vacuum setting
- Table / view / index / trigger counts
- Total row count across all tables
- Per-table breakdown: rows, columns, blob column count, proportional bar chart

### 🔒 Security
| Concern | How it's handled |
|---------|-----------------|
| CSRF | `random_bytes(32)` token; verified with `hash_equals()` on every request |
| SQL injection | All table/column names escaped via `qid()` (double-quote doubling); user values use `?` bound parameters |
| Table/column injection | Every user-supplied name whitelisted against `sqlite_master` via `assertTbl()` / `assertCol()` |
| Path traversal | `realpath()` verified against `sys_get_temp_dir()` before opening any file |
| Read-only | `PRAGMA query_only=ON` enforced on every connection — viewer cannot modify data |
| Upload validation | Extension whitelist + SQLite magic byte check (`SQLite format 3`) + PDO open test |
| Clickjacking | `X-Frame-Options: SAMEORIGIN` header |
| MIME sniffing | `X-Content-Type-Options: nosniff` header |

---

## Requirements

- PHP **8.0+**
- Extensions: `pdo_sqlite`, `mbstring`, `fileinfo` (usually enabled by default)
- A web server (Apache, Nginx, Caddy, or PHP's built-in server)

---

## Installation

```bash
# 1. Download the single file
curl -O https://raw.githubusercontent.com/yourname/sqlens/main/sqlens.php

# 2. Serve it
php -S localhost:8080 sqlens.php

# 3. Open in browser
open http://localhost:8080/sqlens.php
```

Or just copy `sqlens.php` into any directory served by Apache/Nginx. That's it.

---

## Usage

1. Open `sqlens.php` in your browser
2. Drag & drop a `.sqlite` / `.db` / `.sqlite3` / `.s3db` file, or click **Choose File**
3. Watch the upload progress bar — file is validated server-side before anything is shown
4. Browse tables from the sidebar, sort/filter/paginate as needed
5. Use the search bar to query across all tables at once
6. Export any view to **CSV** or **PDF**
7. Click **↓ Download** on any blob cell to save the binary
8. Click **Statistics** in the sidebar for database internals
9. Click **Schema** to view the raw `CREATE TABLE` SQL for the active table
10. Click **✕ Close** to end the session and delete the temp file

---

## Storage & Privacy

| What | Where | How long |
|------|-------|----------|
| Uploaded file | `sys_get_temp_dir()` (e.g. `/tmp/sqlens_XXXXXXXX`) | Until user clicks Close, or next upload overwrites it |
| Session data | PHP session (file path, filename, file size) | Until session expires or `Close` is clicked |
| Anything else | — | Nothing else is stored |

No data is written outside the system temp directory. No logs. No database. No analytics.

> **Tip for production:** add a cron job to clean up orphaned temp files from abandoned sessions:
> ```bash
> # Delete sqlens temp files older than 1 hour
> find /tmp -name 'sqlens_*' -mmin +60 -delete
> ```

---

## File Support

| Extension | Notes |
|-----------|-------|
| `.db` | Most common SQLite extension |
| `.sqlite` | Explicit SQLite extension |
| `.sqlite3` | SQLite 3 specific |
| `.s3db` | Legacy SQLite 3 extension |

Encrypted databases (e.g., SQLCipher) are not supported and will be rejected with an error.

---

## Limitations

- **Read-only** — no query editor, no data modification by design
- **Single user per session** — each browser session gets its own temp file
- **Max upload size** — governed by PHP's `upload_max_filesize` and `post_max_size` directives
- **Search limit** — 200 rows per table in search results, 500 in CSV export
- No support for encrypted or password-protected SQLite databases

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | PHP 8.0+, PDO SQLite |
| Frontend | Vanilla JS (no frameworks) |
| Fonts | [Outfit](https://fonts.google.com/specimen/Outfit) + [JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono) |
| PDF export | [jsPDF](https://github.com/parallax/jsPDF) + [AutoTable](https://github.com/simonbengtsson/jsPDF-AutoTable) |

---

## Live Demo

Live demonstration of this project is hosted here: https://ckure.org/rx/sql
---

## License

MIT — do whatever you want, just don't remove the file header.

---

<p align="center">Built as a single PHP file. No composer. No npm. No config. Just drop and go.</p>
