#!/usr/bin/env python3
"""Adds a mod to this store: zips its files and updates manifest.json.

Example:
  python add_mod.py "C:\\path\\to\\MyMod" --name "My Mod" --creator hatchson --version 1.0.0 --game orion-drift --summary "What it does" --tags visuals,fun

Every mod needs --game, an id from manifest.json's games[] list. Unreal Engine
games need a matching .utoc, .ucas and .pak; other engines accept any files.
Only add mods you made or have permission to share.
"""
import argparse
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import modscan

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.json"
GITHUB_LIMIT = 100 * 1024 * 1024  # GitHub rejects larger single files


def main():
    ap = argparse.ArgumentParser(description="Add a mod to this store.")
    ap.add_argument("folder", type=Path, help="folder or .zip holding the .utoc, .ucas and .pak")
    ap.add_argument("--name", required=True)
    ap.add_argument("--creator", required=True)
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--summary", default="")
    ap.add_argument("--description", default="")
    ap.add_argument("--tags", default="", help="comma separated")
    ap.add_argument("--game", default="orion-drift", help="game id from manifest.json games[] (e.g. orion-drift)")
    ap.add_argument("--id", help="defaults to a cleaned-up name")
    a = ap.parse_args()

    mod_id = a.id or re.sub(r"[^a-z0-9]+", "-", a.name.lower()).strip("-")
    if not re.fullmatch(r"[A-Za-z0-9][\w.\-]{0,79}", mod_id):
        sys.exit(f"'{mod_id}' is not a usable id. Pass one with --id using letters, numbers, dots or dashes.")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    games = {g.get("id"): g for g in manifest.get("games", [])}
    if a.game not in games:
        sys.exit(f"Unknown game '{a.game}'. Add it to manifest.json games[] first. Known: {', '.join(sorted(games)) or 'none'}.")
    engine = str(games[a.game].get("engine", "ue")).lower()

    if not a.folder.exists():
        sys.exit(f"{a.folder} does not exist.")
    tmp = None
    if a.folder.is_file():
        if a.folder.suffix.lower() != ".zip":
            sys.exit("Pass a folder or a .zip holding the mod's files.")
        tmp = tempfile.TemporaryDirectory()
        with zipfile.ZipFile(a.folder) as z:
            z.extractall(tmp.name)
        files = Path(tmp.name).rglob("*")
    else:
        files = a.folder.iterdir()
    root = Path(tmp.name) if tmp else a.folder

    if engine == "ue":
        stems = {}
        for f in files:
            if f.is_file() and f.suffix.lower() in (".utoc", ".ucas", ".pak"):
                stems.setdefault(f.stem, {})[f.suffix.lower()] = f
        complete = {s: fs for s, fs in stems.items() if len(fs) == 3}
        if not complete:
            sys.exit("No complete patch found. For Unreal Engine games the folder needs a .utoc, .ucas and .pak with the same name.")
        pack = [f for fs in complete.values() for f in fs.values()]
    else:
        pack = [f for f in files if f.is_file()]
        if not pack:
            sys.exit("The folder has no files to pack.")

    out_dir = HERE / "mods" / mod_id
    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / f"{mod_id}.zip"
    # Pack into a temporary file first: a refused publish must never overwrite
    # the zip that is already on the store.
    staged = out_dir / f".{mod_id}.staged.zip"
    with zipfile.ZipFile(staged, "w", zipfile.ZIP_DEFLATED) as z:
        for f in pack:
            z.write(f, f.name if engine == "ue" else f.relative_to(root).as_posix())
    if tmp:
        tmp.cleanup()
    data = staged.read_bytes()
    if len(data) > GITHUB_LIMIT:
        staged.unlink(missing_ok=True)
        if tmp:
            tmp.cleanup()
        sys.exit("The zip is over GitHub's 100 MB file limit, so it can't be hosted here.")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    # --- scan gate (modscan.py) -------------------------------------------
    # Nothing below this line runs unless the zip is clean: no executables,
    # scripts or droppers, no downloader/exfil strings, no NSFW or banned
    # names - and never a copy of a mod that is already on the store, whoever
    # claims to have made it.
    findings = modscan.check_metadata(a.name, a.creator, a.summary,
                                      a.description or a.summary,
                                      [t for t in a.tags.split(",") if t.strip()], mod_id)
    zfind, member_hashes, fp = modscan.scan_zip_bytes(data)
    findings += zfind
    findings += modscan.store_conflicts(manifest, mod_id, a.creator, fp,
                                        hashlib.sha256(data).hexdigest(), a.name)
    if findings:
        staged.unlink(missing_ok=True)
        try:
            out_dir.rmdir()  # only succeeds if the folder is now empty
        except OSError:
            pass
        print(f"REFUSED {a.name}: nothing was written.", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        sys.exit(1)

    staged.replace(archive)  # the scan passed - the published zip changes now

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = {
        "id": mod_id,
        "name": a.name,
        "creator": a.creator,
        "version": a.version,
        "summary": a.summary,
        "description": a.description or a.summary,
        "game": a.game,
        "tags": [t.strip() for t in a.tags.split(",") if t.strip()],
        "updated": now,
        "fp": fp,
        "files": [{
            "name": archive.name,
            "url": f"mods/{mod_id}/{archive.name}",
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }],
    }
    mods = [m for m in manifest["mods"] if m.get("id") != mod_id]
    replaced = len(mods) != len(manifest["mods"])
    mods.append(entry)
    manifest["mods"] = mods
    manifest["updated"] = now
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{'Updated' if replaced else 'Added'} {a.name} [{a.game}]: {len(data)} bytes, {len(pack)} file(s). Commit and push to publish it.")


if __name__ == "__main__":
    main()
