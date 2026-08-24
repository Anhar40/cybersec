# CyberSec AI Agent

Autonomous web-security terminal agent berbasis conversational AI. Bicara bahasa natural — agent yang memeriksa environment, menyiapkan tool, menjalankan reconnaissance dan vulnerability assessment secara terkendali, mendiagnosis error sendiri, lalu menyusun laporan Markdown dari bukti (evidence) yang terkumpul.

Ditenagai oleh [OpenRouter](https://openrouter.ai) — model bisa diganti kapan saja lewat environment variable.

## Fitur

- **Agent loop dengan streaming** — balasan model tampil kata demi kata secara live
- **Terminal aman** — tanpa shell mentah; semua command divalidasi sebagai array argv (`shell=False`), lolos safety gate, dibatasi rate limit dan budget sesi
- **Penghapusan file terkurasi** — `file_delete` dengan guard lokasi sistem, status per-target, dan konfirmasi wajib
- **Risk tier + konfirmasi** — aksi LOW-risk jalan otomatis; MEDIUM/HIGH selalu minta persetujuan `y/N`
- **Error recovery cerdas** — kegagalan diklasifikasi, diberi hint perbaikan terstruktur, dan tidak pernah diulang buta (maks 3 retry per aksi identik)
- **Tool Manager** — inventaris tool, instalasi via package manager terdeteksi, verifikasi pasca-install
- **Web Security & Recon** — curl, nmap, httpx, whatweb, nikto, nuclei, ffuf, dig, openssl, subfinder
- **Vulnerability Assessment** — `vuln_scan` (nuclei, temuan terstruktur) dan `sqli_probe` (sqlmap profil aman: batch, risk=1)
- **Evidence & Reporting** — ledger temuan per-sesi dengan auto-capture, laporan Markdown siap pakai

## Persyaratan

| Kebutuhan | Ketentuan |
|---|---|
| Python | >= 3.10 |
| pip & git | bawaan/ikut terpasang |
| API key OpenRouter | daftar di openrouter.ai, ambil key dari dashboard |
| Tool eksternal | opsional — dipasang sesuai kebutuhan assessment (lihat bagian [Tool Eksternal](#tool-eksternal-opsional)) |

---

## Instalasi

### Windows (PowerShell)

```powershell
git clone https://github.com/Anhar40/cybersec.git
cd cyberaent

python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -e .
```

> Jika perintah `python` tidak dikenali, ganti dengan `py`: `py -m venv .venv`

Jalankan:

```powershell
$env:OPENROUTER_API_KEY="sk-or-v1-xxxx"
$env:OPENROUTER_MODEL="google/gemini-2.0-flash-001"
.venv\Scripts\cyberaent.exe
```

Atau agar tidak perlu set ulang tiap sesi, buat file `.env` di root proyek:

```env
OPENROUTER_API_KEY=sk-or-v1-xxxx
OPENROUTER_MODEL=google/gemini-2.0-flash-001
```

lalu cukup jalankan `.venv\Scripts\cyberaent.exe`.

### Linux (Debian/Ubuntu dan turunannya)

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/Anhar40/cybersec.git
cd cyberaent

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
```

Jalankan:

```bash
export OPENROUTER_API_KEY="sk-or-v1-xxxx"
export OPENROUTER_MODEL="google/gemini-2.0-flash-001"
.venv/bin/cyberaent
```

Agar permanen, tambahkan dua baris `export` di atas ke `~/.bashrc` (atau `~/.zshrc`), lalu `source ~/.bashrc`. Cara lain: buat file `.env` di root proyek seperti contoh Windows.

Distribusi non-Debian tinggal sesuaikan installer venv-nya (mis. `sudo dnf install python3-pip` di Fedora) — langkah venv dan run identik.

> **Penting untuk WSL:** jangan pernah membuat ulang `.venv` dari dalam WSL pada folder yang sama dengan instalasi Windows (`/mnt/c/...`, `/mnt/d/...`). Venv Windows dan Linux tidak kompatibel — keduanya akan saling merusak. Dari WSL, pakai nama terpisah:
>
> ```bash
> python3 -m venv .venv-linux
> .venv-linux/bin/pip install -e .
> .venv-linux/bin/cyberaent
> ```

### Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install -y python git

git clone https://github.com/Anhar40/cybersec.git
cd cyberaent

python -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e .
```

Jalankan:

```bash
export OPENROUTER_API_KEY="sk-or-v1-xxxx"
export OPENROUTER_MODEL="google/gemini-2.0-flash-001"
.venv/bin/cyberaent
```

Simpan env permanen ke `~/.bashrc` atau gunakan file `.env` seperti di atas.

> Catatan Termux: inti aplikasi (chat, streaming, reporting) ringan karena hanya butuh `httpx` dan `rich` (pure Python). Tool scanning berat seperti nuclei lebih lambat dibangun di HP — pertimbangkan memasangnya hanya bila benar dipakai.

---

## Konfigurasi

| Variable | Wajib? | Default | Keterangan |
|---|---|---|---|
| `OPENROUTER_API_KEY` | ya | — | Key dari dashboard OpenRouter |
| `OPENROUTER_MODEL` | ya | — | Id model bebas, mis. `openai/gpt-4o-mini`, `anthropic/claude-3.5-sonnet`, `google/gemini-2.0-flash-001` |
| `OPENROUTER_BASE_URL` | tidak | `https://openrouter.ai/api/v1` | Ganti jika memakai endpoint kompatibel OpenAI |

Prioritas pembacaan: environment variable > file `.env` di folder proyek.

---

## Cara Pakai

Setelah banner muncul, ketik instruksi bahasa natural (Indonesia/Inggris):

```text
You > cek tool apa saja yang sudah terinstall
You > audit header https://target-saya.com
You > lakukan recon pada example.com lalu rangkum temuannya
You > scan target ini pakai nuclei severity high ke atas
You > kenapa ffuf saya error?
You > install nmap
You > buatkan laporan penetration testing
```

Slash command yang tersedia:

| Command | Fungsi |
|---|---|
| `/help` | Bantuan |
| `/history` | Riwayat command yang dieksekusi |
| `/findings` | Lihat evidence ledger temuan saat ini |
| `/report` | Tulis laporan Markdown ke folder `reports/` |
| `/clear` | Reset konteks percakapan |
| `/exit`, `/quit` | Keluar |

Alur keamanan yang akan kamu rasakan:

- Aksi berisiko rendah (cek versi, baca header) jalan otomatis
- Aksi aktif (port scan, fuzzing, sqlmap) selalu muncul panel konfirmasi `y/N`
- Target di luar scope yang kamu izinkan ditolak
- Setiap tool gagal menghasilkan panel DIAGNOSIS dengan saran perbaikan

Hasil report tersimpan di `reports/report-YYYYMMDD-HHMMSS.md`; riwayat command di `logs/commands.jsonl`.

---

## Tool Eksternal (opsional)

Aplikasi inti jalan tanpa tool ini. Pasang seperlunya — agent akan mendeteksi, mengusulkan instalasi, dan memverifikasi otomatis.

| Tool | Dipakai untuk | Debian/Ubuntu | Termux | Windows |
|---|---|---|---|---|
| curl | HTTP request, header audit | biasanya sudah ada | sudah ada | sudah ada (Win10+) |
| nmap | port scan | `sudo apt install nmap` | `pkg install nmap` | `winget install Insecure.Nmap` |
| dig | DNS lookup | `sudo apt install dnsutils` | `pkg install dnsutils` | BIND tools / WSL |
| openssl | TLS info | biasanya sudah ada | `pkg install openssl` | ikut Git for Windows |
| whatweb | fingerprinting teknologi | `sudo apt install whatweb` | build dari source (Ruby) | via Ruby/WSL |
| nikto | scanner web klasik | `sudo apt install nikto` | `pkg install nikto` | WSL disarankan |
| httpx | probe massal URL | lihat catatan Go | `pkg install golang` lalu go install | binary release / go install |
| nuclei | vulnerability scan | lihat catatan Go | idem | binary release / go install |
| subfinder | enumerasi subdomain | lihat catatan Go | idem | binary release / go install |
| ffuf | directory fuzzing | lihat catatan Go | idem | binary release / go install |
| sqlmap | sqli_probe | `pip install sqlmap` | `pip install sqlmap` | `pip install sqlmap` |

Catatan Go — contoh pola pemasangan projectdiscovery:

```bash
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/ffuf/ffuf/v2@latest
```

Alternatif tanpa Go: unduh binary rilis dari GitHub masing-masing project lalu letakkan di PATH.

Tidak yakin sudah terpasang? Tanya saja agent-nya: `You > cek apakah nuclei sudah terinstall`.

---

## Development

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"      # Windows: .venv\Scripts\python.exe

.venv/bin/python -m pytest tests -q              # test suite
.venv/bin/python -m ruff check cyberaent tests   # lint
.venv/bin/python -m mypy cyberaent tests         # type check
```

## Keamanan & Etika

Gunakan hanya pada target yang **anda miliki atau memiliki izin eksplisit** untuk diuji. Sistem ini dirancang menolak destruktivitas: tidak ada dump data, tidak ada web shell, tidak ada DoS, dan aksi di luar scope diblokir. Anda tetap sepenuhnya bertanggung jawab atas penggunaannya.
