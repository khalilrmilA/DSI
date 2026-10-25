# Borne Forum DSI — Next Step

Kiosk tactile du Forum DSI 2026 + vérification d'exposition de domaine
(« Vos identifiants ont-ils fuité ? ») branchée sur votre cluster Elasticsearch.

## Déploiement production (Docker — recommandé)

Tout tourne en conteneurs : l'application **+ MongoDB**. Sur le serveur :

```bash
cp .env.docker.example .env      # puis éditez les mots de passe et ES_URL
docker compose up -d --build
```

- Borne       → `http://<serveur>:8080`
- Super-admin → `http://<serveur>:8080/superadmin`
- MongoDB : service interne, données persistées dans le volume `mongo-data`.

Logs / arrêt / mise à jour :

```bash
docker compose logs -f app
docker compose down             # arrête (garde les données)
docker compose up -d --build    # redéploie après modif
```

> Elasticsearch n'est **pas** dans la stack : l'app le joint via `ES_URL` sur le réseau
> du serveur. Si ES tourne sur le même hôte Docker, mettez `ES_URL=http://host.docker.internal:9200`
> et décommentez `extra_hosts` dans `docker-compose.yml`.

### Variables (fichier `.env`, voir `.env.docker.example`)

| Variable | Défaut | Rôle |
|---|---|---|
| `MONGO_USER` / `MONGO_PASS` | `admin` / `changeme` | identifiants MongoDB |
| `MONGO_DB` | `forum_dsi` | base de données |
| `APP_PORT` | `8080` | port exposé sur le serveur |
| `ES_URL` | `http://10.9.21.32:9200` | cluster Elasticsearch |
| `ES_INDEX` | `leaks_data` | index/alias des fuites |
| `ES_USER` / `ES_PASS` | — | basic auth ES (si activée) |
| `ADMIN_USER` / `ADMIN_PASS` | `superadmin` / `Admin@2026` | **identifiants super-admin par défaut — à changer** |

## Lancer en local (développement)

Nécessite une instance MongoDB accessible (ex. `docker run -d -p 27017:27017 mongo:7`).

```bash
npm install
MONGO_URL=mongodb://localhost:27017 npm start
# → http://localhost:8080
```

Node 18+ requis. Autres variables : `PORT`, `HOST`, `ES_TIMEOUT_MS`,
`RATE_MAX` / `RATE_WINDOW_MS`, `MONGO_DB`.

## Architecture

```
navigateur (borne)  ─┐
                     ├─> app (Node, conteneur)  ──> MongoDB (conteneur, volume)
  /superadmin  ──────┘        │ garde ES_URL + secrets côté serveur
                              └─> Elasticsearch <serveur>:9200 / leaks_data
```

La borne est une page statique : un navigateur **ne peut pas** joindre directement
`10.9.21.32` (CORS + réseau privé), et il ne faut jamais exposer Elasticsearch ni
l'adresse `10.9.21.32` au navigateur. Le petit serveur Node sert donc la page **et**
fait proxy vers Elasticsearch ; l'URL du cluster reste dans le process Node.

## La vérification de fuites

- Nouvelle tuile d'accueil **« Vos identifiants ont-ils fuité ? »** → parcours
  `Coordonnées → Domaine → Résultat` (comme l'analyse de posture).
- Le front appelle `POST /api/leak-check` avec `{ domain, authorized:true }`.
- Le serveur interroge `leaks_data` et ne renvoie **que des agrégats** :
  - nombre total d'enregistrements pour le domaine ;
  - comptes `@domaine` exposés (`domain`) et accès à vos services (`url_domain`) ;
  - cardinalité (comptes distincts), services les plus touchés, pays, logiciels, année ;
  - date de la fuite la plus récente ;
  - jusqu'à 5 exemples d'identifiants **masqués** (`sa••••@domaine`).

### Garde-fous (défense, pas offensive)

- **Les mots de passe ne sont jamais demandés à Elastic ni renvoyés.** Le champ
  `password` est d'ailleurs `index:false` dans le mapping. Les identifiants d'exemple
  sont masqués côté serveur.
- **Autorisation obligatoire** : sans la case « je suis habilité(e) à vérifier ce
  domaine » cochée, l'API répond 403.
- **Validation + limitation de débit** par IP, pour que la borne ne devienne pas un
  outil de recherche en masse.
- L'adresse d'Elasticsearch n'apparaît jamais dans le code chargé par le navigateur.

## Base de données & journaux (MongoDB)

Tout est enregistré dans **MongoDB** (`MONGO_DB`, défaut `forum_dsi`), deux collections :

- `leads` — un document par visiteur (clé unique `ref` ; re-sauvegarde = mise à jour) :
  coordonnées, besoins, offre retenue, résultats de fuites…
- `events` — journal d'usage : écrans vus, parcours lancés/terminés, vérifications de
  fuites (avec `hit`/volume), sauvegardes de leads.

La borne envoie ces données automatiquement (`/api/lead`, `/api/event`). Les données
persistent dans le volume Docker `mongo-data` (sauvegardez-le, ou faites des `mongodump`).

## Super-admin (statistiques + journaux)

La page n'est liée nulle part dans la borne : tapez l'adresse à la main,
**http://localhost:8080/superadmin** (ou `/super-admin`), puis connectez-vous.

Identifiants par défaut : **`superadmin` / `Admin@2026`** (variables `ADMIN_USER` /
`ADMIN_PASS`). Changez-les depuis la section **« Compte super-admin »** du tableau de
bord : ils sont alors stockés hachés (scrypt) dans MongoDB et priment sur les variables
d'environnement. Une session dure 12 h (`ADMIN_SESSION_HOURS`) ; 10 échecs de connexion
par IP bloquent la connexion 15 min. Connexions, échecs et changements de paramètres
apparaissent dans les journaux.

Le tableau de bord montre, en temps réel (bouton auto-actualisation) :

- **KPIs** : visiteurs, offres, demandes cloud, analyses, vérifs de fuites, domaines
  exposés, taux d'exposition, parcours terminés.
- **Ce qui plaît le plus** : parcours choisi (Offre / Analyse / Fuites), mix de domaines,
  priorités SOC les plus demandées, services cloud les plus demandés, niveau d'offre
  retenu, secteurs, fonctions, échéances EPP et infrastructure.
- **Activité** : progression dans le parcours (écrans vus), affluence par heure,
  domaines vérifiés pour les fuites, endpoints moyens, synthèse fuites, activité par jour.
- **Données** : table des visiteurs + table des journaux (avec recherche), et **export CSV**.

> La borne garde aussi son mini-admin local (appui long sur le logo, code `2026`).
> Le super-admin ci-dessus est la vue serveur complète et durable.

### Source de données : Elasticsearch ou API ScanBe4

Dans le super-admin, section **« Paramètres — source de données »**, on choisit d'où
viennent les fuites et on branche l'API ScanBe4 :

- **Source des fuites** : `Elasticsearch (interne)` ou `ScanBe4 API`.
- **ScanBe4 — API fuites (GET)** : `https://scanbe4.com/api/v1/leaks` (récupère les données).
- **ScanBe4 — API scan (POST)** : `https://scanbe4.com/api/v1/scans` (lance une analyse).
- **ScanBe4 — Jeton (Bearer)** : votre `sb4_lk_…`.

Le **jeton est stocké en base côté serveur** et n'est jamais renvoyé en clair au
navigateur (affiché masqué, ex. `••••cJ0`). Un bouton **« Tester la connexion »**
vérifie la source active sur `example.com`. Les réglages sont stockés dans MongoDB
(collection `settings`) et priment sur les variables d'environnement.

Comportement selon la source :

- **Vérification de fuites** (`/api/leak-check`) interroge la source active. Avec ScanBe4,
  la borne agrège un échantillon récent (`total`, comptes distincts, sites touchés,
  pays, années, exemples **masqués**) — jamais de mot de passe.
- **Analyse de posture** : quand ScanBe4 est configuré, valider le domaine déclenche un
  vrai scan via `POST /api/v1/scans` (avec `notify_email` = e-mail du visiteur).

## Endpoints

| Méthode | Chemin | Accès | Réponse |
|---|---|---|---|
| `GET` | `/` et fichiers statiques | public | la borne (`public/`) |
| `GET` | `/superadmin` | public (page) | tableau de bord (données protégées) |
| `GET` | `/api/health` | public | `{ ok, es:"up"\|"down", index }` |
| `POST` | `/api/leak-check` | public* | agrégats sûrs (source active) |
| `POST` | `/api/scan` | public* | déclenche un scan ScanBe4 |
| `POST` | `/api/lead` | public* | enregistre un visiteur |
| `POST` | `/api/event` | public* | enregistre un événement d'usage |
| `POST` | `/api/admin/login` | public | `{ user, pass }` → `{ token }` (session) |
| `POST` | `/api/admin/logout` | jeton | ferme la session |
| `POST` | `/api/admin/credentials` | jeton | change identifiant / mot de passe |
| `GET` | `/api/admin/stats` | jeton | statistiques agrégées |
| `GET` | `/api/admin/leads` | jeton | derniers visiteurs |
| `GET` | `/api/admin/events` | jeton | derniers journaux |
| `GET` | `/api/admin/export.csv` | jeton | export CSV des visiteurs |
| `GET/POST` | `/api/admin/settings` | jeton | lire / modifier la source de données |
| `POST` | `/api/admin/test` | jeton | tester la source active |

\* appelés par la borne elle-même ; `leak-check` est validé + limité en débit par IP.
Le jeton de session (renvoyé par `/api/admin/login`) se passe en `Authorization: Bearer <jeton>` (ou `?token=` pour le CSV).

## Fichiers

```
server/server.mjs       serveur HTTP + proxy ES + API admin
server/db.mjs           couche MongoDB (collections leads / events)
public/index.html       la borne (votre artefact) + fuites + journal d'usage
public/superadmin.html  tableau de bord super-admin
Dockerfile              image de l'app
docker-compose.yml      stack app + MongoDB
.env.docker.example     variables pour docker compose
package.json            dépendances (mongodb) + npm start
```

## Intégration à la borne

Ajouts faits dans `public/index.html` (reste identique à votre artefact) :
`freshState().leak`, `FLOWS.leak`, la carte `fn` de `render`, la branche de
redirection de `vContact`, la tuile d'accueil `data-start="leak"`, les vues
`vLeak` / `vLeakResult`, et un bloc CSS « vérification de fuites ».
