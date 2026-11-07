#!/usr/bin/env python3
"""Scans mod zips for malware, junk and NSFW, and fingerprints them so a copy
of an already-published mod can never be re-posted under a new name.

    python modscan.py "C:\\path\\to\\Mod.zip"         scan one zip, exit 1 if blocked
    python modscan.py Mod.zip --name "My Mod" --creator you
                                                     ...and judge it the way a
                                                     publish would be judged
    python modscan.py --all                          scan every mod in mods/, stamp
                                                     each manifest entry with its
                                                     fingerprint, audit the store

The same rules run in index.html (publish in the browser) - the two must stay in
step, so any rule changed here gets mirrored there. What this catches:

  malware   Windows/script executables, scripts, droppers, PowerShell and
            shellcode strings, token exfil (Discord webhooks), downloader C2s
  nsfw      adult terms in file names, mod names, descriptions and text files
  names     slurs, scams, grabbers and other names that should never ship
  copies    a content fingerprint that survives re-zipping and renaming: the
            same files in the same bytes give the same fingerprint, so pulling
            a mod off the store and re-uploading it is refused, not re-licensed

It reads bytes; it does not run anything and it does not need the network.
Exit codes: 0 clean, 1 blocked / problems found.
"""
import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.json"

# ---------------------------------------------------------------- rules ----
# Executables, scripts and droppers: never belong inside a mod zip.
BLOCK_EXT = {
    ".exe", ".dll", ".scr", ".msi", ".msp", ".mst", ".com", ".pif", ".cpl",
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".sh", ".bash", ".zsh", ".fish",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".class",
    ".apk", ".dex", ".odex", ".smali", ".reg", ".scf", ".lnk", ".url", ".svg",
    ".html", ".htm", ".mhtml", ".pdf", ".py", ".rb", ".pl", ".php", ".lua",
}
# Native libraries are allowed on Quest, but only real ELF ones.
NATIVE_OK = {".so"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".lz4"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tga", ".ico"}
TEXT_EXT = {".txt", ".md", ".json", ".cfg", ".ini", ".xml", ".yaml", ".yml",
            ".csv", ".log", ".toml", ".info", ".manifest", ".version", ".cs", ".cfg2"}

# Names that never ship: adult terms, slurs, scams, stealer vocabulary.
# Matching: phrases match anywhere; words of 5+ letters match inside a word;
# shorter words must match a whole word, so "class" and "document" pass.
BAD_WORDS = {
    # adult / NSFW
    "nsfw", "hentai", "rule34", "r34", "porn", "porno", "onlyfans", "xvideos",
    "xnxx", "boobs", "boob", "tits", "titties", "penis", "vagina", "anus",
    "nude", "nudes", "naked", "fetish", "milf", "futa", "e621", "gelbooru",
    "danbooru", "loli", "shota", "underage", "sex", "sexy", "cum", "cumshot",
    # slurs and insults
    "nigger", "nigga", "faggot", "retard", "tranny", "kike", "spic", "chink",
    "wetback", "fag", "dyke",
    # scams, stealers, remote access
    "grabber", "stealer", "keylogger", "tokenlogger", "token logger",
    "free nitro", "nitro gift", "steam gift", "airdrop", "backdoor", "rat",
    "remote access", "webshell", "trojan", "keylog", "ratelimit bypass",
}

# Strings that mean "this file is doing something to your machine".
PAYLOAD_PATTERNS = [
    # script / shell cradles
    "frombase64string", "invoke-expression", "invoke-webrequest", "iex(",
    "iex ", "net.webclient", "downloadstring", "downloadfile",
    "start-bitstransfer", "certutil", "bitsadmin", "mshta", "rundll32",
    "regsvr32", "cmd.exe", "powershell", "-executionpolicy", "add-mppreference",
    "excludepath", "defender exclusion", "schtasks", "runonce",
    "currentversion\\run", "currentversion/run", "wscript.shell", "activexobject",
    "shellexecute", "getasynckeystate", "setwindowshex", "keyboardlog",
    "vbc.exe", "cscript", "wscript", "net user", "localgroup administrators",
    "add-mppreference", "disable realtime", "uninstall-string", "hkey_local_machine",
    # exfil and drop points
    "discord.com/api/webhooks", "discordapp.com/api/webhooks", "pastebin.com/raw",
    "hastebin", "ghostbin", "transfer.sh", "webhook.site", "requestbin",
    "ngrok.io", "ngrok-free", "trycloudflare.com", ".onion",
    "mimikatz", "procdump", "lsass", "schtasks /create",
]
# A Discord bot token sitting in a file is an exfiltrated credential.
TOKEN_RE = re.compile(rb"[a-z0-9_\-]{23,28}\.[a-z0-9_\-]{6,7}\.[a-z0-9_\-]{25,110}",
                      re.IGNORECASE)

MAGIC_BLOCKS = [
    (b"MZ", "a Windows executable"),
    (b"#!", "a shell/interpreter script"),
    (b"%PDF", "a PDF document"),
    (b"{\\rtf", "an RTF document"),
    (b"<script", "inline script"),
    (b"<html", "an HTML page"),
    (b"<svg", "inline SVG"),
    (b"<?php", "PHP code"),
]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(member_hashes) -> str:
    """Content fingerprint: same bytes in the zip, same fingerprint - even if the
    zip was rebuilt with other compression or the files were renamed."""
    return sha256_hex("\n".join(sorted(member_hashes)).encode("utf-8"))


def bad_words_in(text):
    if not text:
        return []
    low = text.lower()
    norm = re.sub(r"[^a-z0-9]+", "", low)
    tokens = [t for t in re.split(r"[^a-z0-9]+", low) if t]
    hits = []
    for w in BAD_WORDS:
        if " " in w:
            if re.sub(r"[^a-z0-9]+", "", w) in norm:
                hits.append(w)
        elif len(w) >= 5:
            if w in norm:
                hits.append(w)
        elif w in tokens:
            hits.append(w)
    return sorted(set(hits))


def _text_of(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", "replace")


def scan_member(name: str, data: bytes):
    """Return a list of blocking findings for one file inside the zip."""
    out = []
    base = name.split("/")[-1]
    ext = ("." + base.rsplit(".", 1)[-1].lower()) if "." in base else ""

    if ext in BLOCK_EXT:
        out.append(f"'{base}' is {ext} - code, scripts, documents and link files "
                   f"are not allowed in a mod zip.")
    if ext in ARCHIVE_EXT:
        out.append(f"'{base}' is an archive inside the mod. Unzip it first - "
                   f"only the mod's own files go in.")
    hits = bad_words_in(base)
    if hits:
        out.append(f"'{base}' contains a name that will not be published ({', '.join(hits)}).")

    head = data[:16]
    if ext in NATIVE_OK:
        if not head.startswith(b"\x7fELF"):
            out.append(f"'{base}' claims to be a native library but is not a real ELF file.")
    else:
        for magic, what in MAGIC_BLOCKS:
            if data[:len(magic)].lower() == magic.lower():
                out.append(f"'{base}' is {what} wearing a mod's file name.")
                break
        if head.startswith(b"\x7fELF"):
            out.append(f"'{base}' is a compiled Linux binary - not a mod file.")
        if head.startswith(b"PK"):
            out.append(f"'{base}' is a nested archive. Extract it and pack the files.")

    if ext in IMAGE_EXT and not any(
        data[:len(m)] == m for m in (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"BM")
    ) and not data[:4] in (b"\x00\x00\x01\x00",):
        out.append(f"'{base}' says it is an image but its bytes are something else.")

    hay = data.lower()
    for pat in PAYLOAD_PATTERNS:
        if pat.encode() in hay:
            out.append(f"'{base}' contains '{pat}' - a downloader/exfil string, not mod content.")
            break
    if len(data) % 2 == 0:
        try:
            hay16 = data.decode("utf-16-le", "ignore").lower().encode("utf-8", "ignore")
        except Exception:
            hay16 = b""
        for pat in PAYLOAD_PATTERNS:
            if pat.encode() in hay16:
                out.append(f"'{base}' contains '{pat}' in UTF-16 - a script payload, not mod content.")
                break
    if TOKEN_RE.search(data):
        out.append(f"'{base}' contains a Discord token - stolen credentials do not belong in a mod.")

    if ext in TEXT_EXT:
        for w in bad_words_in(_text_of(data)):
            out.append(f"'{base}' contains text that will not be published ({w}).")
    return out


def scan_zip_bytes(data: bytes):
    """Full scan of a zip. Returns (findings, member_hashes, fp)."""
    findings = []
    hashes = []
    try:
        zf = zipfile.ZipFile(__import__("io").BytesIO(data))
    except Exception as e:
        return [f"That file is not a readable zip ({e})."], [], ""
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if not infos:
        return ["That zip is empty - there is nothing to publish."], [], ""
    for info in infos:
        raw = zf.read(info)
        hashes.append(sha256_hex(raw))
        findings += scan_member(info.filename, raw)
    return findings, hashes, fingerprint(hashes)


def scan_zip_path(path: Path):
    return scan_zip_bytes(Path(path).read_bytes())


def check_metadata(name, creator, summary, description, tags, mod_id=""):
    """Mod-level checks: what the row is called, who is claiming it."""
    findings = []
    for label, value in (("mod name", name), ("creator", creator),
                         ("summary", summary), ("description", description),
                         ("tags", " ".join(tags or [])), ("id", mod_id)):
        for w in bad_words_in(value or ""):
            findings.append(f"The {label} contains '{w}', which will not be published.")
    if not (name or "").strip():
        findings.append("The mod needs a name.")
    if not (creator or "").strip():
        findings.append("The mod needs a creator.")
    return findings


def store_conflicts(manifest, mod_id, creator, fp, zip_sha, name=""):
    """Refuse to publish a mod that is already on the store.

    Two independent locks:
      content  - the same files (fingerprint) or the exact zip may only ever be
                 written back under the *original id*, so a copy can never be
                 posted as a new mod, whoever claims to have made it.
      identity - an id or name already in the store keeps its creator; taking
                 over somebody's row is refused.
    """
    findings = []
    norm = lambda s: re.sub(r"\s+", " ", (s or "").strip().lower())
    mod_id, creator, name = norm(mod_id), norm(creator), norm(name)
    for entry in manifest.get("mods", []):
        eid, ename = norm(entry.get("id", "")), norm(entry.get("name", ""))
        label = f"'{entry.get('name')}' by {entry.get('creator')}"
        if fp and entry.get("fp") == fp and eid != mod_id:
            findings.append(f"This is a copy of {label}, already on the store. "
                            f"Updates go back under its own id - a copy cannot be published as a new mod.")
        for f in entry.get("files", []):
            if zip_sha and f.get("sha256") == zip_sha and eid != mod_id:
                findings.append(f"This is the exact file already published as {label}.")
        if mod_id and eid == mod_id and norm(entry.get("creator", "")) != creator:
            findings.append(f"The id '{entry.get('id')}' belongs to {label}. "
                            f"Renaming the creator on somebody else's mod is not allowed.")
        if name and ename == name and norm(entry.get("creator", "")) != creator:
            findings.append(f"'{entry.get('name')}' is already on the store as {label}.")
    seen, unique = set(), []
    for f in findings:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


# ------------------------------------------------------------------ CLI ----
def cmd_check(path: Path, name="", creator=""):
    """Content scan plus, when --name/--creator are given, the exact judgement
    add_mod.py would make for a brand-new mod here."""
    data = path.read_bytes()
    findings, hashes, fp = scan_zip_bytes(data)
    print(f"{path.name}: {len(hashes)} file(s), fingerprint {fp[:16]}...")
    sha = sha256_hex(data)
    if name or creator:
        mod_id = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
        findings += check_metadata(name, creator, "", "", [], mod_id)
        if MANIFEST.exists():
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            findings += store_conflicts(manifest, mod_id, creator, fp, sha, name)
    elif MANIFEST.exists() and fp:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        findings += store_conflicts(manifest, "", "", fp, sha, "")
    for f in findings:
        print(f"  BLOCK  {f}")
    if not findings:
        print("  clean - no malware, no NSFW, no banned names, not already on the store.")
    print(f"  sha256 {sha}")
    return 1 if findings else 0


def cmd_all():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    mods = manifest.get("mods", [])
    seen = {}
    problems = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for entry in mods:
        mid = entry.get("id", "?")
        files = entry.get("files") or []
        if not files:
            problems.append(f"{mid}: no files listed")
            continue
        path = HERE / files[0].get("url", "")
        if not path.exists():
            problems.append(f"{mid}: missing on disk ({files[0].get('url')})")
            continue
        data = path.read_bytes()
        actual = sha256_hex(data)
        if files[0].get("sha256") != actual:
            problems.append(f"{mid}: manifest sha256 does not match the file on disk")
        findings, hashes, fp = scan_zip_bytes(data)
        for f in findings:
            problems.append(f"{mid}: {f}")
        if fp in seen:
            problems.append(f"{mid}: identical content to '{seen[fp]}' - two copies on the store")
        seen[fp] = mid
        if entry.get("fp") != fp:
            entry["fp"] = fp
            print(f"stamped {mid}: fp {fp[:16]}... ({len(hashes)} files, {len(data)} bytes)")
        else:
            print(f"ok      {mid}: fp {fp[:16]}... ({len(hashes)} files, {len(data)} bytes)")

    # cross-check names/owners the same way a submission would be judged
    for entry in mods:
        conflicts = store_conflicts(
            manifest, entry.get("id", ""), entry.get("creator", ""), entry.get("fp", ""),
            (entry.get("files") or [{}])[0].get("sha256", ""), entry.get("name", ""))
        for c in conflicts:
            if c not in problems:
                problems.append(f"{entry.get('id')}: {c}")

    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\n{len(mods)} mod(s) scanned at {now}.")
    if problems:
        print("PROBLEMS:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("problems: 0")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Scan mod zips and fingerprint them.")
    ap.add_argument("--all", action="store_true",
                    help="scan every mod in mods/, stamp fingerprints, audit the store")
    ap.add_argument("path", nargs="?", type=Path, help="zip to scan (omit for --all)")
    ap.add_argument("--name", default="", help="with a zip: judge it as this mod name")
    ap.add_argument("--creator", default="", help="with a zip: judge it as this creator")
    a = ap.parse_args()
    if a.all or not a.path:
        sys.exit(cmd_all())
    if not a.path.exists():
        sys.exit(f"{a.path} does not exist.")
    sys.exit(cmd_check(a.path, a.name, a.creator))


if __name__ == "__main__":
    main()
