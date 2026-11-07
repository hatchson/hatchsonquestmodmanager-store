# Hatchson's Quest Mod Manager Store

The mod store for **Hatchson's Quest Mod Manager**, hosted free on GitHub Pages.

## Links

- **Store address** (enter in the manager under **Settings > Mod store**): `https://hatchson.github.io/hatchsonquestmodmanager-store/`
- **Store site (submit, review and publish mods):** `https://hatchson.github.io/hatchsonquestmodmanager-store/`
- **Manifest:** `https://hatchson.github.io/hatchsonquestmodmanager-store/manifest.json`

The manager loads `manifest.json`, groups every mod by game, and shows each game's
engine (Unreal Engine or Unity) so the right install path is used.

## Multi-game manifest

`manifest.json` has two parts:

- `games[]` — the catalog every mod's `game` field points at:

```json
{ "id": "orion-drift", "name": "Orion Drift", "package": "com.AnotherAxiom.A2", "engine": "ue" }
```

  `engine` is `"ue"` or `"unity"`. `package` is the Android package the manager
  looks for when auto-detecting installed games on the Quest.

- `mods[]` — each entry carries `"game": "<game id>"`:

```json
{ "id": "cosmeticz", "name": "CosmeticZ", "game": "orion-drift", "files": [ ... ] }
```

Old mods without a `game` field still load; they group under **Other**.

### Add a game to the catalog

Edit `manifest.json` and append to `games[]`:

```json
{ "id": "my-game", "name": "My Game", "package": "com.studio.mygame", "engine": "unity" }
```

Commit and push — the manager and the publish page both pick it up on their
next refresh.

## Publish it

The store files (`manifest.json`, `add_mod.py`, this README, `.nojekyll`, `logo.png`
and the `mods/` folder) live at the root of the `hatchson/hatchsonquestmodmanager-store`
repository.

1. Create the repository `hatchson/hatchsonquestmodmanager-store` on GitHub and push this folder to `main`.
2. In the repository, open **Settings > Pages**, set the source to **Deploy from a branch**, and choose `main` and `/ (root)`.
3. After a minute or two, this address works: `https://hatchson.github.io/hatchsonquestmodmanager-store/manifest.json`
4. In the manager, open **Settings > Mod store**, enter `https://hatchson.github.io/hatchsonquestmodmanager-store/`, and press **Save and load**.

The empty `.nojekyll` file makes GitHub Pages serve every file as is. Keep it.
There is intentionally **no `CNAME` file** — a CNAME would hijack the project URL.

## Add a mod

Only add mods you made or have the creator's permission to share. The repository is public, so anyone can download them.

```
python add_mod.py "C:\path\to\MyMod" --name "My Mod" --creator you --version 1.0.0 --game orion-drift --summary "What it does" --tags visuals,fun
```

`--game` is required in practice (it defaults to `orion-drift`) and must be an id
from `manifest.json` `games[]`:

- **Unreal Engine games** (`engine: "ue"`): the folder or `.zip` needs a matching
  `.utoc`, `.ucas` and `.pak`. They are packed flat into the mod zip.
- **Other engines** (`engine: "unity"` etc.): any files are packed as-is, keeping
  their folder structure.

Run it from your clone of this repository, since it writes `mods/` and
`manifest.json` next to itself. Run the command again with the same name to update
a mod, then push the changes.

## Publish from the browser (GitHub Pages mode)

Open the store site — no password, no sign-in. The page reads `manifest.json` like
anybody else, because GitHub Pages is read-only for everybody: **you** are the
publisher, and your publishing rights are your push access to this repository.

1. **Add your mod's zip** (step 2). Unreal Engine games keep only a complete
   `.utoc` / `.ucas` / `.pak` set with the same name, flattened to the zip's root.
   Every other game keeps its files and folder structure as they are.
2. **Describe it** (step 3): name, who made it, version, game, summary, tags.
3. Press **Download release bundle**. You get `release-bundle-<id>-v<version>.zip`
   containing exactly two things:
   - `mods/<id>/<id>.zip` — the mod, already repacked and checksummed
   - `manifest.json` — the whole manifest with your entry written in, with `bytes`
     and `sha256` computed for you
4. Extract the bundle **into your clone of this repository** so it covers
   `manifest.json`, then commit and push.

GitHub Desktop: extract, drag the files into the repo folder, commit, push.
Terminal, from the repo folder:

```powershell
Expand-Archive -Path release-bundle-<id>-v<version>.zip -DestinationPath . -Force
git add -A
git commit -m "publish <mod name>"
git push
```

GitHub Pages serves the new files about a minute after the push, and the manager
picks them up on its next **Save and load**.

**Updating:** press **Update** on the mod's row in *Already in the store*, drop the
new zip, raise the version, press **Download update bundle** — same extract-and-push.
**Deleting:** press **Delete**, extract that bundle, *and* delete the mod's
`mods/<id>/` folder before you commit.

Every bundle carries the whole manifest, so publish one mod at a time and push
in between — otherwise the last bundle you extract wins and drops the others.

## Optional: an upload server

Nothing above needs one. If you ever want a password-gated web form that commits
for you (and accepts guest submissions for review), the Cloudflare Worker lives
**outside this repository** in `../optional-cloudflare/`:

- `worker/worker.js`, `worker/wrangler.toml`
- `.github/workflows/deploy-worker.yml`

To turn it on: copy `worker/` and `.github/workflows/` back into this repository,
add the repository secrets **Settings > Secrets and variables > Actions** —
`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `UPLOAD_PASSWORD`,
`STORE_GITHUB_TOKEN` (fine-grained, this repository, **Contents: Read and write**)
— push, then set `LOCAL` to `false` at the top of `index.html` so `UPLOAD_API`
points at your worker's address.

Do not copy the workflow in before the secrets exist: it runs on every push that
touches `worker/**`, so the first push would go red until they are set. That is why
both files live outside the repository for now.

## Local tooling

- `add_mod.py` — Python 3, standard library only. The quickest way to publish a mod
  from your own machine: it packs the zip, writes `manifest.json`, and you push.
- `../optional-cloudflare/worker/worker.js` — the optional upload server.
