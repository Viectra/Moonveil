# Règles du projet & Économie de tokens

## Règles Git du dépôt
- Ne travaille que sur la branche `tatsuya`.
- Fais des commits dans le style exemple : `main.py fix : correction de la division par zero dans le calcul principal`.
- Ne push pas si l'utilisateur ne le demande pas explicitement.

## Règles impératives de travail & d'économie de tokens

1. **Lecture ciblée obligatoire :**
   - Toujours lire `ARCHITECTURE.md` en premier au début de chaque session pour localiser les fichiers concernés.
   - Interdiction de scanner récursivement le projet (`ls -R`, `find`, `grep` global large) si l'emplacement du code ou du module est déjà indiqué dans `ARCHITECTURE.md`.

2. **Exclusion stricte des fichiers lourds :**
   - Ne jamais lire les fichiers de données volumineux, lockfiles (`Cargo.lock`), dossiers de build (`target/`, `dist/`, `build/`), dépendances (`node_modules/`, `.venv/`) ou assets binaires (`assets/*.png`) sauf autorisation explicite de l'utilisateur.

3. **Modifications chirurgicales :**
   - Lire (par plages de lignes ciblées) et modifier uniquement les fichiers strictement nécessaires à la tâche demandée.
   - Privilégier les éditions ciblées plutôt que la réécriture complète de gros fichiers.

4. **Modularité :**
   - Éviter les fichiers monolithiques ; si un module dépasse ~400–500 lignes lors d'un ajout de fonctionnalité, le découper proprement en sous-modules cohérents.

5. **Maintenance de la carte :**
   - Mettre à jour `ARCHITECTURE.md` (en restant strictement sous les 300 lignes et à exactement 1 ligne par fichier) uniquement lorsqu'un fichier est ajouté, déplacé, renommé ou supprimé.

6. **Commandes de build & tests :**
   - Toujours exécuter les commandes de compilation, lint et tests au **premier plan** et attendre leur fin complète (ne jamais les lancer en arrière-plan sans attendre le résultat).
   - Commandes exactes détectées dans le projet (`Cargo.toml` / `Makefile`) :
     - Tests : `cargo test` (ou `make test`)
     - Build release : `cargo build --release` (ou `make build`)
     - Build Linux statique : `cargo build --release --target x86_64-unknown-linux-musl` (ou `make build-linux`)
     - Lint & format : `cargo fmt --check && cargo clippy --all-targets -- -D warnings` (ou `make lint`)
     - Formatage : `cargo fmt` (ou `make fmt`)
     - Exécution démo : `cargo run -- --demo` (ou `make demo`)
