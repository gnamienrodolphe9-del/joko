# JOKO V1

Opportunités fiables pour les jeunes de 16 à 30 ans à Abidjan : fil filtrable, statuts de confiance, signalement d'arnaques, modération.

## Structure
```
joko/
├─ index.html       point d'entrée à la racine (hors de public/) → redirige vers public/index.html
├─ server.js        serveur Node.js : API + fichiers de public/
├─ schema.sql       création des 6 tables PostgreSQL
├─ seed.sql         6 offres d'exemple (ne pas charger en production)
├─ package.json     dépendances et démarrage
├─ .env.example     modèle de configuration (copier en .env)
├─ .gitignore       exclut .env et node_modules de GitHub
└─ public/          application web (index.html, admin.html, sw.js, manifest.json, icon.svg)
```

## Lancer en local
1. `npm install`
2. Copier `.env.example` en `.env` et le remplir (DATABASE_URL, JWT_SECRET, PHONE_KEY, ADMIN_PHONE).
3. Créer les tables : exécuter `schema.sql` (puis `seed.sql` pour les offres d'exemple) dans la base `joko`.
4. `node server.js` puis ouvrir http://localhost:3000 (back-office : /admin.html).
Le terminal doit afficher « Base de données connectée ✔ ».

## GitHub et GitHub Pages
GitHub stocke le code. Il n'exécute ni Node.js ni PHP.
GitHub Pages (Settings > Pages > Deploy from a branch > main, dossier /root) peut afficher l'interface via index.html,
mais sans serveur Node.js la connexion et les offres ne fonctionnent pas (aperçu visuel seulement).
Sur le plan gratuit, GitHub Pages exige un dépôt public ; le site est public même si le dépôt est privé (plans payants).
Ne jamais publier le fichier `.env` (déjà exclu par `.gitignore`).

## Hébergement (Node.js + PostgreSQL)
Commande d'installation : `npm install` · Commande de démarrage : `node server.js`
Variables : DATABASE_URL, BDD_SSL (true si exigé), JWT_SECRET, PHONE_KEY, ADMIN_PHONE, NODE_ENV=production, SEUIL.
Avant d'ouvrir au public : brancher la passerelle SMS dans la fonction `envoyerSms` de server.js.

## Variables d'environnement
| Variable | Rôle |
|---|---|
| DATABASE_URL | adresse de la base PostgreSQL |
| JWT_SECRET, PHONE_KEY | secrets (64 caractères chacun, à ne jamais changer après les premières inscriptions pour PHONE_KEY) |
| ADMIN_PHONE | numéro (avec +225) qui devient administrateur à sa première connexion |
| SEUIL | signalements confirmés avant le statut SIGNALÉE (3 par défaut) |
| BDD_SSL | `true` si l'hébergeur exige SSL pour la base |
| AFFICHER_CODE_TEST | `true` : le code SMS s'affiche à l'écran (mode test, sans fournisseur SMS) |
| CONNEXION_RAPIDE | `true` UNIQUEMENT dans le .env local : boutons de connexion rapide sans SMS (jamais sur Railway) |
| CHARGER_OFFRES_TEST | `true` : charge les offres d'exemple si la table est vide (à retirer avant l'ouverture au public) |

## Espace recruteur et candidatures
- Le rôle (« Je cherche du travail » ou « Je recrute ») est choisi à la connexion, à la création du compte, puis il est fixe.
- Un recruteur a sa propre interface (Accueil, Mes offres, Profil) et ne voit que ses propres offres, jamais celles des autres recruteurs ni celles de l'équipe.
- Le rôle est relu dans la base à chaque requête : un changement de rôle ou une suspension s'applique tout de suite.
- Un recruteur publie une offre avec son contrat : Journée, Plusieurs jours, CDD, CDI ou À la tâche, plus durée et rémunération.
- Toute offre reste « en attente de validation » jusqu'à la validation d'un modérateur (back-office).
- Un chercheur postule en un geste ; le recruteur voit prénom, compétences et numéro des candidats de ses offres uniquement.
- Le recruteur peut clôturer une offre : elle disparaît du fil et n'accepte plus de candidatures.

## Installation sur l'écran d'accueil (PWA)
- À l'ouverture du lien, Chrome (Android, ordinateur) déclenche une invitation « Installe JOKO » avec un bouton Installer. Sur iPhone (Safari), elle explique le geste Partager > Sur l'écran d'accueil.
- Condition : adresse en HTTPS (Railway) ou localhost. Si l'invitation est fermée ou refusée, elle revient après 7 jours.
- Fichiers : public/manifest.json, public/sw.js (service worker), icônes public/icon-192.png, icon-512.png, icon-maskable-512.png, icon-180.png.
- Pour la revoir pendant les tests : console du navigateur > `localStorage.removeItem('invitationReportee')`, puis recharger.
