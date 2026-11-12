// JOKO V1 — serveur (API + fichiers de l'application)
const chemin = require('path');
require('dotenv').config({ path: chemin.join(__dirname, '.env') }); // charge le fichier .env à côté de server.js
const express = require('express'), { Pool } = require('pg'), jwt = require('jsonwebtoken'),
  crypto = require('crypto'), limiteur = require('express-rate-limit'), helmet = require('helmet');

if (!process.env.DATABASE_URL) {
  console.error('ERREUR : DATABASE_URL est absent. Vérifiez le fichier .env (à côté de server.js).');
  process.exit(1);
}
const bdd = new Pool({ connectionString: process.env.DATABASE_URL });
const SECRET_JWT = process.env.JWT_SECRET || 'secret-de-developpement';
const SEUIL_SIGNALEMENTS = +process.env.SEUIL || 3; // signalements confirmés avant statut SIGNALÉE
const CLE_CHIFFREMENT = crypto.createHash('sha256').update(process.env.PHONE_KEY || 'cle-de-developpement').digest();

const hacher = (texte) => crypto.createHmac('sha256', CLE_CHIFFREMENT).update(texte).digest('hex');
const chiffrer = (texte) => {
  const vecteur = crypto.randomBytes(12), chiffreur = crypto.createCipheriv('aes-256-gcm', CLE_CHIFFREMENT, vecteur);
  const contenu = Buffer.concat([chiffreur.update(texte), chiffreur.final()]);
  return Buffer.concat([vecteur, chiffreur.getAuthTag(), contenu]).toString('base64');
};
const normaliserTelephone = (saisie) => {
  let numero = String(saisie || '').replace(/[\s.-]/g, '');
  if (/^\d{10}$/.test(numero)) numero = '+225' + numero;
  return /^\+\d{8,15}$/.test(numero) ? numero : null;
};
const envoyerSms = async (telephone, message) => console.log('[SMS]', telephone, message); // À remplacer par la passerelle SMS

const appli = express();
appli.use(helmet({ contentSecurityPolicy: false }), express.json({ limit: '20kb' }), express.static(chemin.join(__dirname, 'public')));
appli.use('/api', limiteur({ windowMs: 60000, max: 120 }));
const limiteCodeSms = limiteur({ windowMs: 60000, max: 5, message: { error: 'Trop de demandes, réessayez dans 1 minute' } });

const gererErreurs = (fonction) => (requete, reponse, suite) =>
  fonction(requete, reponse, suite).catch((erreur) => { console.error('ERREUR SERVEUR :', erreur); reponse.status(500).json({ error: 'Erreur serveur' }); });
const exigerConnexion = (rolesAutorises) => (requete, reponse, suite) => {
  try {
    requete.utilisateur = jwt.verify((requete.headers.authorization || '').slice(7), SECRET_JWT);
    if (rolesAutorises && !rolesAutorises.includes(requete.utilisateur.role)) return reponse.status(403).json({ error: 'Interdit' });
    suite();
  } catch { reponse.status(401).json({ error: 'Non connecté' }); }
};
const exigerModerateur = exigerConnexion(['moderator', 'admin']);
const journaliserAction = (idModerateur, objet, decision, motif) =>
  bdd.query('insert into mod_log(moderator_id,object,decision,reason) values($1,$2,$3,$4)', [idModerateur, objet, decision, motif || '']);

// ---------- F-01 Connexion par téléphone + code SMS ----------
appli.post('/api/auth/otp/request', limiteCodeSms, gererErreurs(async (requete, reponse) => {
  const telephone = normaliserTelephone(requete.body.phone);
  if (!telephone) return reponse.status(400).json({ error: 'Numéro invalide' });
  const code = String(crypto.randomInt(100000, 1000000));
  await bdd.query("insert into otps values($1,$2,now()+interval '5 minutes',0) on conflict(phone_hash) do update set code_hash=$2,expires_at=now()+interval '5 minutes',attempts=0",
    [hacher(telephone), hacher(telephone + code)]);
  await envoyerSms(telephone, `JOKO : votre code est ${code}`);
  reponse.json({ ok: true, ...(process.env.NODE_ENV !== 'production' && { dev_code: code }) });
}));

appli.post('/api/auth/otp/verify', limiteCodeSms, gererErreurs(async (requete, reponse) => {
  const telephone = normaliserTelephone(requete.body.phone);
  const demandeCode = telephone && (await bdd.query('select * from otps where phone_hash=$1', [hacher(telephone)])).rows[0];
  if (!demandeCode || demandeCode.expires_at < new Date() || demandeCode.attempts >= 5)
    return reponse.status(400).json({ error: "Code expiré ou trop d'essais" });
  if (demandeCode.code_hash !== hacher(telephone + String(requete.body.code || ''))) {
    await bdd.query('update otps set attempts=attempts+1 where phone_hash=$1', [hacher(telephone)]);
    return reponse.status(400).json({ error: 'Code incorrect' });
  }
  await bdd.query('delete from otps where phone_hash=$1', [hacher(telephone)]);
  const roleInitial = process.env.ADMIN_PHONE && normaliserTelephone(process.env.ADMIN_PHONE) === telephone ? 'admin' : 'user';
  const utilisateur = (await bdd.query(
    "insert into users(phone_hash,phone_enc,name,role) values($1,$2,$3,$4) on conflict(phone_hash) do update set name=coalesce(nullif($3,''),users.name),role=case when $4='admin' then 'admin' else users.role end returning id,name,role,suspended",
    [hacher(telephone), chiffrer(telephone), String(requete.body.name || '').slice(0, 60), roleInitial])).rows[0];
  if (utilisateur.suspended) return reponse.status(403).json({ error: 'Compte suspendu' });
  reponse.json({ token: jwt.sign({ id: utilisateur.id, role: utilisateur.role }, SECRET_JWT, { expiresIn: '7d' }), user: { name: utilisateur.name, role: utilisateur.role } });
}));

// ---------- F-02 / F-03 / F-04 Fil d'offres, statuts, fiche ----------
appli.get('/api/opportunities', gererErreurs(async (requete, reponse) => {
  const conditions = ["o.moderation='approved'"], valeurs = [];
  const ajouterCondition = (sql, valeur) => { valeurs.push(valeur); conditions.push(sql.replace('?', '$' + valeurs.length)); };
  const { type, city, availability, q: recherche, page } = requete.query;
  if (type) ajouterCondition('o.type=?', type);
  if (city) ajouterCondition("(o.city=? or o.city='En ligne')", city);
  if (availability) ajouterCondition("(o.availability=? or o.availability='Flexible')", availability);
  if (recherche) { valeurs.push('%' + String(recherche).slice(0, 60) + '%'); conditions.push(`(o.title ilike $${valeurs.length} or o.description ilike $${valeurs.length})`); }
  const decalage = (Math.max(1, +page || 1) - 1) * 20;
  reponse.json((await bdd.query(
    `select o.id,o.title,o.type,o.city,o.availability,o.status,o.created_at,(select count(*) from reports r where r.opportunity_id=o.id)::int as reports from opportunities o where ${conditions.join(' and ')} order by o.created_at desc limit 20 offset ${decalage}`, valeurs)).rows);
}));

appli.get('/api/opportunities/:id', gererErreurs(async (requete, reponse) => {
  const offre = (await bdd.query("select * from opportunities where id=$1 and moderation='approved'", [+requete.params.id])).rows[0];
  if (!offre) return reponse.status(404).json({ error: 'Offre introuvable' });
  if (offre.status === 'SIGNALEE') offre.contact = null;
  offre.reports = (await bdd.query('select kind,amount,created_at from reports where opportunity_id=$1 order by created_at desc', [offre.id])).rows;
  reponse.json(offre);
}));

// ---------- F-05 Signalement ----------
appli.post('/api/reports', exigerConnexion(), gererErreurs(async (requete, reponse) => {
  const { opportunity_id: idOffre, kind: typeProbleme, amount: montant } = requete.body;
  if (!['Argent demandé', 'Offre fictive', 'Contact injoignable'].includes(typeProbleme)) return reponse.status(400).json({ error: 'Type invalide' });
  const { n: signalementsDuJour } = (await bdd.query("select count(*)::int n from reports where user_id=$1 and created_at>now()-interval '1 day'", [requete.utilisateur.id])).rows[0];
  if (signalementsDuJour >= 20) return reponse.status(429).json({ error: "Trop de signalements aujourd'hui" });
  await bdd.query('insert into reports(opportunity_id,user_id,kind,amount) values($1,$2,$3,$4) on conflict do nothing', [+idOffre, requete.utilisateur.id, typeProbleme, montant ? +montant : null]);
  reponse.json({ ok: true });
}));

// ---------- F-07 / F-08 Compétences et suggestions ----------
appli.get('/api/me/skills', exigerConnexion(), gererErreurs(async (requete, reponse) =>
  reponse.json((await bdd.query('select skill from user_skills where user_id=$1', [requete.utilisateur.id])).rows.map((ligne) => ligne.skill))));
appli.put('/api/me/skills', exigerConnexion(), gererErreurs(async (requete, reponse) => {
  const competences = (requete.body.skills || []).slice(0, 20).map((c) => String(c).slice(0, 40));
  await bdd.query('delete from user_skills where user_id=$1', [requete.utilisateur.id]);
  for (const competence of competences) await bdd.query('insert into user_skills values($1,$2) on conflict do nothing', [requete.utilisateur.id, competence]);
  reponse.json({ ok: true });
}));
appli.get('/api/me/suggestions', exigerConnexion(), gererErreurs(async (requete, reponse) => {
  const motifs = (await bdd.query('select skill from user_skills where user_id=$1', [requete.utilisateur.id])).rows.map((ligne) => `%${ligne.skill}%`);
  reponse.json((await bdd.query("select id,title,type,city,availability,status,created_at from opportunities where moderation='approved' and status<>'SIGNALEE' order by (title ilike any($1) or description ilike any($1)) desc,created_at desc limit 5", [motifs.length ? motifs : ['%']])).rows);
}));

// ---------- Notifications ----------
appli.get('/api/me/notifications', exigerConnexion(), gererErreurs(async (requete, reponse) => {
  const nouvellesOffres = (await bdd.query("select id,'Nouvelle offre : '||title as t,type||' · '||city as d,created_at as at from opportunities where moderation='approved' and status<>'SIGNALEE' and created_at>now()-interval '14 days' order by created_at desc limit 5")).rows;
  const signalementsTraites = (await bdd.query("select r.opportunity_id as id,'Ton signalement a été traité' as t,o.title as d,r.decided_at as at from reports r join opportunities o on o.id=r.opportunity_id where r.user_id=$1 and r.decided_at is not null order by r.decided_at desc limit 5", [requete.utilisateur.id])).rows;
  reponse.json([...nouvellesOffres, ...signalementsTraites].sort((a, b) => new Date(b.at) - new Date(a.at)).slice(0, 10));
}));

// ---------- F-06 Back-office de modération ----------
appli.get('/api/admin/opportunities', exigerModerateur, gererErreurs(async (requete, reponse) =>
  reponse.json((await bdd.query('select * from opportunities where moderation=$1 order by created_at', [requete.query.status === 'pending' ? 'pending' : requete.query.status || 'pending'])).rows)));
appli.post('/api/admin/opportunities', exigerModerateur, gererErreurs(async (requete, reponse) => {
  const o = requete.body;
  reponse.json((await bdd.query('insert into opportunities(title,type,city,availability,description,contact,source) values($1,$2,$3,$4,$5,$6,$7) returning id', [o.title, o.type, o.city, o.availability || 'Flexible', o.description, o.contact, o.source || 'Équipe'])).rows[0]);
}));
appli.patch('/api/admin/opportunities/:id', exigerModerateur, gererErreurs(async (requete, reponse) => {
  const { decision, reason: motif, status: statut } = requete.body;
  const nouvelEtat = { approve: 'approved', reject: 'rejected', needs_info: 'needs_info' }[decision];
  if (!nouvelEtat) return reponse.status(400).json({ error: 'Décision invalide' });
  await bdd.query('update opportunities set moderation=$2,status=coalesce($3,status) where id=$1', [+requete.params.id, nouvelEtat, ['VERIFIEE', 'A_VERIFIER'].includes(statut) ? statut : null]);
  await journaliserAction(requete.utilisateur.id, 'offre #' + requete.params.id, decision, motif);
  reponse.json({ ok: true });
}));
appli.get('/api/admin/reports', exigerModerateur, gererErreurs(async (requete, reponse) =>
  reponse.json((await bdd.query('select r.*,o.title from reports r join opportunities o on o.id=r.opportunity_id where r.confirmed is null order by r.created_at')).rows)));
appli.patch('/api/admin/reports/:id', exigerModerateur, gererErreurs(async (requete, reponse) => {
  const signalement = (await bdd.query('update reports set confirmed=$2,decided_at=now() where id=$1 returning opportunity_id,user_id', [+requete.params.id, !!requete.body.confirm])).rows[0];
  if (!signalement) return reponse.status(404).json({ error: 'Signalement introuvable' });
  const { n: signalementsConfirmes } = (await bdd.query('select count(*)::int n from reports where opportunity_id=$1 and confirmed', [signalement.opportunity_id])).rows[0];
  const seuilAtteint = signalementsConfirmes >= SEUIL_SIGNALEMENTS;
  if (seuilAtteint) await bdd.query("update opportunities set status='SIGNALEE' where id=$1", [signalement.opportunity_id]);
  await journaliserAction(requete.utilisateur.id, 'signalement #' + requete.params.id, requete.body.confirm ? 'confirmé' : 'rejeté', requete.body.reason);
  reponse.json({ ok: true, status_changed: seuilAtteint });
}));
appli.post('/api/admin/users/:id/suspend', exigerModerateur, gererErreurs(async (requete, reponse) => {
  await bdd.query('update users set suspended=true where id=$1', [+requete.params.id]);
  await journaliserAction(requete.utilisateur.id, 'user #' + requete.params.id, 'suspendu', requete.body.reason);
  reponse.json({ ok: true });
}));
appli.get('/api/admin/dashboard', exigerModerateur, gererErreurs(async (requete, reponse) => reponse.json({
  offres: (await bdd.query('select status,count(*)::int n from opportunities group by 1')).rows,
  signalements_7j: (await bdd.query("select count(*)::int n from reports where created_at>now()-interval '7 days'")).rows[0].n,
  delai_moyen_h: (await bdd.query('select round(avg(extract(epoch from decided_at-created_at)/3600)::numeric,1) h from reports where decided_at is not null')).rows[0].h,
  journal: (await bdd.query('select * from mod_log order by created_at desc limit 30')).rows,
})));

const PORT = process.env.PORT || 3000;
bdd.query('select 1').then(() => console.log('Base de données connectée ✔'))
  .catch((erreur) => console.error('ERREUR : connexion à la base impossible →', erreur.message));
appli.listen(PORT, () => console.log('JOKO prêt sur http://localhost:' + PORT));
