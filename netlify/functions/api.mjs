import { getStore } from "@netlify/blobs";
import {
  createHash, createHmac, randomBytes, randomUUID, scrypt, timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";
import webpush from "web-push";

const scryptAsync = promisify(scrypt);

const FILIERES = ["GI", "RT"];
const NIVEAUX = ["L1", "L2", "L3"];
const KINDS = ["schedule", "notes", "resultats", "rattrapage", "communiques"];
const MAX_PDF = 5 * 1024 * 1024;
const TOKEN_TTL = 30 * 24 * 3600;
const ANNEE_DEFAUT = "2026-2027";

if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || "mailto:admin@inptic.ga",
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const store = () => getStore({ name: "campus", consistency: "strong" });

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const sha256 = (v) => createHash("sha256").update(v).digest();
const normEmail = (v) => (typeof v === "string" ? v.trim().toLowerCase() : "");
const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 200;
const clean = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const emailKey = (email) => "emails/" + sha256(email).toString("hex");

/* ---------- DÉTECTION DU TYPE DE FICHIER (magic bytes) ---------- */

function detectMimeType(buf) {
  if (!buf || buf.length < 4) return null;
  if (buf.slice(0, 5).toString("latin1") === "%PDF-") return "application/pdf";
  if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return "image/jpeg";
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) return "image/png";
  const head6 = buf.slice(0, 6).toString("latin1");
  if (head6 === "GIF87a" || head6 === "GIF89a") return "image/gif";
  if (buf.slice(0, 4).toString("latin1") === "RIFF" && buf.slice(8, 12).toString("latin1") === "WEBP") return "image/webp";
  return null;
}

function safeEqual(a, b) {
  return timingSafeEqual(sha256(String(a)), sha256(String(b)));
}

function sign(payload) {
  const body = b64u(JSON.stringify(payload));
  const sig = b64u(createHmac("sha256", process.env.SESSION_SECRET).update(body).digest());
  return body + "." + sig;
}

function verify(token) {
  if (typeof token !== "string" || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const expected = b64u(createHmac("sha256", process.env.SESSION_SECRET).update(body).digest());
  if (!safeEqual(sig, expected)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!p.exp || p.exp < Math.floor(Date.now() / 1000)) return null;
    return p;
  } catch { return null; }
}

async function hashPassword(pw) {
  const salt = randomBytes(16);
  const key = await scryptAsync(pw, salt, 64);
  return salt.toString("hex") + ":" + key.toString("hex");
}

async function checkPassword(pw, stored) {
  if (!stored || !stored.includes(":")) return false;
  const [saltHex, keyHex] = stored.split(":");
  const key = await scryptAsync(pw, Buffer.from(saltHex, "hex"), 64);
  const ref = Buffer.from(keyHex, "hex");
  return key.length === ref.length && timingSafeEqual(key, ref);
}

async function readJson(req) {
  try { return await req.json(); }
  catch { throw new HttpError(400, "Requête invalide."); }
}

async function listAll(s, prefix) {
  const { blobs } = await s.list({ prefix });
  const items = await Promise.all(blobs.map((b) => s.get(b.key, { type: "json" })));
  return items.filter(Boolean);
}

const adminUser = () => ({
  id: "admin", nom: "Administrateur", prenom: "Système",
  email: normEmail(process.env.ADMIN_EMAIL || ""), role: "admin"
});

const publicStudent = (st) => ({
  id: st.id, matricule: st.matricule || "", nom: st.nom, prenom: st.prenom,
  filiere: st.filiere, niveau: st.niveau,
  annee: st.annee || ANNEE_DEFAUT,
  email: st.email || "", tel: st.tel || "",
  role: "etudiant"
});

const newSession = (user) =>
  json({
    token: sign({ sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL }),
    user: user.role === "admin" ? user : publicStudent(user)
  });

/* ---------- AUTHENTIFICATION (header OU query param) ---------- */

async function authenticate(req, s) {
  const h = req.headers.get("authorization") || "";
  let token = h.startsWith("Bearer ") ? h.slice(7) : "";

  if (!token) {
    try {
      const url = new URL(req.url);
      token = url.searchParams.get("token") || "";
    } catch {}
  }

  const p = verify(token);
  if (!p) throw new HttpError(401, "Session expirée. Reconnectez-vous.");
  if (p.role === "admin") {
    if (!normEmail(process.env.ADMIN_EMAIL || "")) throw new HttpError(401, "Session expirée. Reconnectez-vous.");
    return { role: "admin", user: adminUser() };
  }
  const st = await s.get("students/" + p.sub, { type: "json" });
  if (!st) throw new HttpError(401, "Compte introuvable. Reconnectez-vous.");
  return { role: "etudiant", user: publicStudent(st), student: st };
}

const requireAdmin = (me) => {
  if (me.role !== "admin") throw new HttpError(403, "Réservé à l'administrateur.");
};

/* ---------- VERROUILLAGE D'ANNÉES ---------- */

const lockedYearKey = (annee) => "locked-years/" + annee;

async function lockYear(s, annee) {
  if (!annee) return;
  await s.setJSON(lockedYearKey(annee), { annee, lockedAt: new Date().toISOString() });
}

async function unlockYear(s, annee) {
  if (!annee) return;
  await s.delete(lockedYearKey(annee));
}

async function isYearLocked(s, annee) {
  if (!annee) return false;
  const r = await s.get(lockedYearKey(annee), { type: "json" });
  return !!r;
}

async function listLockedYears(s) {
  const { blobs } = await s.list({ prefix: "locked-years/" });
  const items = await Promise.all(blobs.map((b) => s.get(b.key, { type: "json" })));
  return items.filter(Boolean).map((x) => x.annee).sort();
}

async function getLockedYearsRoute(s) {
  const years = await listLockedYears(s);
  return json({ years });
}

async function lockYearRoute(s, annee) {
  await lockYear(s, annee);
  return json({ ok: true, annee, locked: true });
}

async function unlockYearRoute(s, annee) {
  await unlockYear(s, annee);
  return json({ ok: true, annee, locked: false });
}

/* ---------- auth ---------- */

async function login(req, s) {
  const { email, password } = await readJson(req);
  const e = normEmail(email);
  if (!e || typeof password !== "string" || !password) {
    throw new HttpError(400, "Saisissez votre e-mail et votre mot de passe.");
  }
  const bad = async () => { await sleep(400); throw new HttpError(401, "E-mail ou mot de passe incorrect."); };

  const adminEmail = normEmail(process.env.ADMIN_EMAIL || "");
  if (adminEmail && e === adminEmail) {
    if (process.env.ADMIN_PASSWORD && safeEqual(password, process.env.ADMIN_PASSWORD)) {
      return newSession(adminUser());
    }
    return bad();
  }
  const id = await s.get(emailKey(e));
  const st = id ? await s.get("students/" + id, { type: "json" }) : null;
  if (!st || !(await checkPassword(password, st.passHash))) return bad();
  return newSession(st);
}

async function signup(req, s) {
  const b = await readJson(req);
  const nom = clean(b.nom, 80), prenom = clean(b.prenom, 80);
  const email = normEmail(b.email);
  const password = typeof b.password === "string" ? b.password : "";
  const anneeChoisie = clean(b.annee, 20) || ANNEE_DEFAUT;

  if (!nom || !prenom || !email) throw new HttpError(400, "Merci de remplir tous les champs.");
  if (!validEmail(email)) throw new HttpError(400, "E-mail invalide.");
  if (password.length < 6 || password.length > 200) throw new HttpError(400, "Le mot de passe doit contenir au moins 6 caractères.");
  if (!FILIERES.includes(b.filiere) || !NIVEAUX.includes(b.niveau)) throw new HttpError(400, "Filière ou niveau invalide.");

  // ✅ Refus si l'année est verrouillée
  if (await isYearLocked(s, anneeChoisie)) {
    throw new HttpError(403, `L'année universitaire ${anneeChoisie} est verrouillée. Contactez l'administrateur.`);
  }

  const adminEmail = normEmail(process.env.ADMIN_EMAIL || "");
  if (adminEmail && email === adminEmail) throw new HttpError(409, "Un compte avec cet e-mail existe déjà.");

  const existingId = await s.get(emailKey(email));
  if (existingId) {
    const st = await s.get("students/" + existingId, { type: "json" });
    if (st && st.passHash) throw new HttpError(409, "Un compte avec cet e-mail existe déjà.");
    if (st) {
      st.passHash = await hashPassword(password);
      if (!st.annee) st.annee = anneeChoisie;
      await s.setJSON("students/" + st.id, st);
      return newSession(st);
    }
  }
  const st = {
    id: randomUUID(), matricule: "", nom, prenom,
    filiere: b.filiere, niveau: b.niveau,
    annee: anneeChoisie,
    email, tel: "",
    role: "etudiant", passHash: await hashPassword(password),
    createdAt: new Date().toISOString()
  };
  await s.setJSON("students/" + st.id, st);
  await s.set(emailKey(email), st.id);
  return newSession(st);
}

/* ---------- données ---------- */

const visibleDoc = (d, st) =>
  (d.filiere === "TOUTES" || d.filiere === st.filiere) &&
  (d.niveau === "TOUS" || d.niveau === st.niveau);

async function getData(me, s) {
  const [students, docs] = await Promise.all([
    me.role === "admin" ? listAll(s, "students/") : Promise.resolve([me.student]),
    listAll(s, "docs/")
  ]);
  const visible = me.role === "admin" ? docs : docs.filter((d) => visibleDoc(d, me.student));
  visible.sort((a, b) => String(b.dateAjout).localeCompare(String(a.dateAjout)));
  students.sort((a, b) => a.nom.localeCompare(b.nom));
  return json({ students: students.map(publicStudent), docs: visible });
}

function studentFields(b, partial) {
  const out = {};
  if (!partial || "nom" in b) { out.nom = clean(b.nom, 80); if (!out.nom) throw new HttpError(400, "Le nom est requis."); }
  if (!partial || "prenom" in b) { out.prenom = clean(b.prenom, 80); if (!out.prenom) throw new HttpError(400, "Le prénom est requis."); }
  if (!partial || "filiere" in b) { if (!FILIERES.includes(b.filiere)) throw new HttpError(400, "Filière invalide."); out.filiere = b.filiere; }
  if (!partial || "niveau" in b) { if (!NIVEAUX.includes(b.niveau)) throw new HttpError(400, "Niveau invalide."); out.niveau = b.niveau; }
  if ("matricule" in b) out.matricule = clean(b.matricule, 40);
  if ("tel" in b) out.tel = clean(b.tel, 40);
  if ("email" in b) {
    const e = normEmail(b.email);
    if (e && !validEmail(e)) throw new HttpError(400, "E-mail invalide.");
    out.email = e;
  }
  return out;
}

async function claimEmail(s, email, id, adminEmail) {
  if (!email) return;
  if (adminEmail && email === adminEmail) throw new HttpError(409, "Cet e-mail est déjà utilisé.");
  const owner = await s.get(emailKey(email));
  if (owner && owner !== id) throw new HttpError(409, "Cet e-mail est déjà utilisé.");
  await s.set(emailKey(email), id);
}

async function createStudent(req, s) {
  const b = await readJson(req);
  const f = studentFields(b, false);
  const st = {
    id: randomUUID(), matricule: "", tel: "", email: "", ...f,
    annee: ANNEE_DEFAUT,
    role: "etudiant", passHash: null, createdAt: new Date().toISOString()
  };
  await claimEmail(s, st.email, st.id, normEmail(process.env.ADMIN_EMAIL || ""));
  await s.setJSON("students/" + st.id, st);
  return json({ student: publicStudent(st) }, 201);
}

async function updateStudent(req, s, id) {
  const st = await s.get("students/" + id, { type: "json" });
  if (!st) throw new HttpError(404, "Étudiant introuvable.");
  const f = studentFields(await readJson(req), true);
  if ("email" in f && f.email !== st.email) {
    await claimEmail(s, f.email, st.id, normEmail(process.env.ADMIN_EMAIL || ""));
    if (st.email) await s.delete(emailKey(st.email));
  }
  Object.assign(st, f);
  await s.setJSON("students/" + id, st);
  return json({ student: publicStudent(st) });
}

async function deleteStudent(s, id) {
  const st = await s.get("students/" + id, { type: "json" });
  if (!st) throw new HttpError(404, "Étudiant introuvable.");
  await s.delete("students/" + id);
  if (st.email) {
    const owner = await s.get(emailKey(st.email));
    if (owner === id) await s.delete(emailKey(st.email));
  }
  await removePushSubsByUser(s, id);
  await deleteBadge(s, id);
  return json({ ok: true });
}

/* ---------- SUPPRESSION FIN D'ANNÉE (+ verrouillage auto) ---------- */

async function purgeYear(s, annee) {
  if (!annee) throw new HttpError(400, "Année scolaire manquante.");

  const stats = { students: 0, docs: 0, files: 0 };

  const students = await listAll(s, "students/");
  const studentsToDelete = students.filter(st => (st.annee || ANNEE_DEFAUT) === annee);

  await Promise.all(studentsToDelete.map(async (st) => {
    await s.delete("students/" + st.id);
    if (st.email) {
      const owner = await s.get(emailKey(st.email));
      if (owner === st.id) await s.delete(emailKey(st.email));
    }
    await removePushSubsByUser(s, st.id);
    await deleteBadge(s, st.id);
    stats.students++;
  }));

  const docs = await listAll(s, "docs/");
  const docsToDelete = docs.filter(doc => (doc.annee || ANNEE_DEFAUT) === annee);

  await Promise.all(docsToDelete.map(async (doc) => {
    await s.delete("docs/" + doc.id);
    await s.delete("files/" + doc.id);
    stats.docs++;
    stats.files++;
  }));

  // ✅ Verrouillage automatique de l'année purgée
  await lockYear(s, annee);

  return json({
    ok: true,
    message: `Toutes les données de l'année ${annee} ont été supprimées. L'année est maintenant verrouillée.`,
    stats,
    locked: true,
    annee
  });
}

/* ---------- SUPPRESSION DE TOUS LES COMMUNIQUÉS ---------- */

async function purgeCommuniques(s) {
  const docs = await listAll(s, "docs/");
  const coms = docs.filter(d => d.kind === "communiques");
  let count = 0;
  await Promise.all(coms.map(async (doc) => {
    await s.delete("docs/" + doc.id);
    await s.delete("files/" + doc.id);
    count++;
  }));
  return json({ ok: true, count, message: `${count} communiqué(s) supprimé(s).` });
}

/* ---------- documents ---------- */

async function uploadDoc(req, s, url) {
  const contentType = req.headers.get("content-type") || "";

  let kind, filiere, niveau, annee, nomFichier, titre, buf, commentaire;

  if (contentType.includes("multipart/form-data")) {
    const formData = await req.formData();
    kind = formData.get("kind");
    filiere = formData.get("filiere");
    niveau = formData.get("niveau");
    annee = formData.get("annee");
    nomFichier = formData.get("nom") || "document.pdf";
    titre = formData.get("titre") || "";
    commentaire = formData.get("commentaire") || "";

    const file = formData.get("file");
    if (!file || typeof file === "string") throw new HttpError(400, "Fichier manquant.");
    buf = Buffer.from(await file.arrayBuffer());
  } else {
    const q = url.searchParams;
    kind = q.get("kind");
    filiere = q.get("filiere");
    niveau = q.get("niveau");
    annee = q.get("annee");
    nomFichier = clean(q.get("nom") || "document.pdf", 200) || "document.pdf";
    titre = clean(q.get("titre") || "", 200);
    commentaire = clean(q.get("commentaire") || "", 1000);
    buf = Buffer.from(await req.arrayBuffer());
  }

  if (!KINDS.includes(kind)) throw new HttpError(400, "Type de document invalide.");
  if (kind === "communiques") { filiere = "TOUTES"; niveau = "TOUS"; annee = "TOUTES"; }
  else if (!FILIERES.includes(filiere) || !NIVEAUX.includes(niveau))
    throw new HttpError(400, "Filière ou niveau invalide.");
  if (!annee) annee = ANNEE_DEFAUT;

  if (!buf.byteLength) throw new HttpError(400, "Fichier vide.");
  if (buf.byteLength > MAX_PDF) throw new HttpError(413, "Fichier trop volumineux (max 5 Mo).");

  // ✅ Détection du type réel du fichier
  const mimeType = detectMimeType(buf);
  if (!mimeType) {
    throw new HttpError(400, "Format non supporté. Utilisez un PDF ou une image (JPG, PNG, GIF, WebP).");
  }
  if (kind !== "communiques" && mimeType !== "application/pdf") {
    throw new HttpError(400, "Le fichier doit être un PDF.");
  }

  nomFichier = clean(nomFichier, 200) || (mimeType === "application/pdf" ? "document.pdf" : "image");
  commentaire = clean(commentaire, 1000);
  titre = clean(titre, 200);

  // ✅ Titre auto-généré si absent
  if (!titre) {
    if (kind === "communiques") {
      titre = "Communiqué du " + new Date().toLocaleDateString("fr-FR");
    } else {
      titre = nomFichier.replace(/\.(pdf|jpg|jpeg|png|gif|webp)$/i, "");
    }
  }

  const id = randomUUID();
  const meta = {
    id, kind, filiere, niveau, annee, titre, nomFichier,
    commentaire,
    mimeType,
    taille: buf.byteLength,
    dateAjout: new Date().toISOString()
  };
  await s.set("files/" + id, buf);
  await s.setJSON("docs/" + id, meta);

  await pushToMatching(s, {
    kind, filiere, niveau,
    title: docKindLabel(kind),
    body: (commentaire || titre) + (kind !== "communiques" ? ` · ${filiere} ${niveau}` : ""),
    url: "/#/" + (kind === "schedule" ? "emploi" : kind)
  });

  return json({ doc: meta }, 201);
}

function docKindLabel(kind) {
  return {
    schedule: "Nouvel emploi du temps",
    notes: "Nouveau relevé de notes",
    resultats: "Nouveau résultat de semestre",
    rattrapage: "Nouveau relevé de rattrapage",
    communiques: "Nouveau communiqué"
  }[kind] || "Nouveau document";
}

/* ---------- DOWNLOAD (Range + ETag + Cache, PDF et images) ---------- */

async function downloadDoc(req, me, s, id, url) {
  const d = await s.get("docs/" + id, { type: "json" });
  if (!d || (me.role !== "admin" && !visibleDoc(d, me.student))) throw new HttpError(404, "Document introuvable.");

  const etag = '"' + id + "-" + (d.taille || 0) + '"';
  const ifNoneMatch = req.headers.get("if-none-match") || "";
  if (ifNoneMatch === etag) {
    return new Response(null, { status: 304, headers: { ETag: etag } });
  }

  const buf = await s.get("files/" + id, { type: "arrayBuffer" });
  if (!buf) throw new HttpError(404, "Fichier introuvable.");

  const total = buf.byteLength;
  const mimeType = d.mimeType || "application/pdf";
  const safeName = encodeURIComponent(d.nomFichier).replace(/['()]/g, escape);
  const forceDownload = url && url.searchParams.get("dl") === "1";
  const disposition = (forceDownload ? "attachment" : "inline") + "; filename*=UTF-8''" + safeName;

  const baseHeaders = {
    "Content-Type": mimeType,
    "Content-Disposition": disposition,
    "Cache-Control": "private, max-age=86400",
    "ETag": etag,
    "Accept-Ranges": "bytes",
    "X-Content-Type-Options": "nosniff"
  };

  const rangeHeader = req.headers.get("range");
  if (rangeHeader && total > 0) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
    if (m) {
      let start = m[1] === "" ? null : parseInt(m[1], 10);
      let end = m[2] === "" ? null : parseInt(m[2], 10);

      if (start === null && end !== null) {
        start = Math.max(0, total - end);
        end = total - 1;
      } else if (start !== null && end === null) {
        end = total - 1;
      }

      if (start === null || end === null || isNaN(start) || isNaN(end) ||
          start > end || start >= total || end >= total) {
        return new Response(null, {
          status: 416,
          headers: { ...baseHeaders, "Content-Range": `bytes */${total}` }
        });
      }

      const chunk = Buffer.from(buf, start, end - start + 1);
      return new Response(chunk, {
        status: 206,
        headers: {
          ...baseHeaders,
          "Content-Range": `bytes ${start}-${end}/${total}`,
          "Content-Length": String(chunk.byteLength)
        }
      });
    }
  }

  return new Response(buf, {
    status: 200,
    headers: { ...baseHeaders, "Content-Length": String(total) }
  });
}

async function deleteDoc(s, id) {
  const d = await s.get("docs/" + id, { type: "json" });
  if (!d) throw new HttpError(404, "Document introuvable.");
  await s.delete("docs/" + id);
  await s.delete("files/" + id);
  return json({ ok: true });
}

/* ---------- passage au niveau supérieur / redoublement ---------- */

const ORDRE_NIVEAUX = ["L1", "L2", "L3"];
function niveauSuivant(niveau){
  const i = ORDRE_NIVEAUX.indexOf(niveau);
  if(i === -1) return niveau;
  if(i === ORDRE_NIVEAUX.length - 1) return "L3";
  return ORDRE_NIVEAUX[i + 1];
}
function anneeSuivante(annee){
  if(!annee || !annee.includes("-")) return annee;
  const [a, b] = annee.split("-").map(Number);
  if(isNaN(a) || isNaN(b)) return annee;
  return `${a + 1}-${b + 1}`;
}

async function passSelf(req, me, s) {
  if (me.role === "admin") throw new HttpError(403, "Action réservée aux étudiants.");
  const st = await s.get("students/" + me.student.id, { type: "json" });
  if (!st) throw new HttpError(404, "Étudiant introuvable.");
  const anneeActuelle = st.annee || ANNEE_DEFAUT;
  const ancienNiveau = st.niveau;
  const nouveauNiveau = niveauSuivant(ancienNiveau);
  const nouvelleAnnee = anneeSuivante(anneeActuelle);
  st.niveau = nouveauNiveau;
  st.annee = nouvelleAnnee;
  await s.setJSON("students/" + st.id, st);

  await pushToUser(s, st.id, {
    title: "🎓 Félicitations !",
    body: `Vous êtes passé(e) en ${nouveauNiveau} pour l'année ${nouvelleAnnee}.`,
    url: "/#/compte"
  });

  return json({
    ok: true,
    ancienNiveau,
    nouveauNiveau,
    ancienneAnnee: anneeActuelle,
    nouvelleAnnee
  });
}

async function repeatSelf(req, me, s) {
  if (me.role === "admin") throw new HttpError(403, "Action réservée aux étudiants.");
  const st = await s.get("students/" + me.student.id, { type: "json" });
  if (!st) throw new HttpError(404, "Étudiant introuvable.");
  const anneeActuelle = st.annee || ANNEE_DEFAUT;
  const niveauConserve = st.niveau;
  const nouvelleAnnee = anneeSuivante(anneeActuelle);

  st.annee = nouvelleAnnee;
  await s.setJSON("students/" + st.id, st);

  await pushToUser(s, st.id, {
    title: "🔁 Redoublement enregistré",
    body: `Vous restez en ${niveauConserve} (${st.filiere}) pour l'année ${nouvelleAnnee}.`,
    url: "/#/compte"
  });

  return json({
    ok: true,
    niveau: niveauConserve,
    filiere: st.filiere,
    ancienneAnnee: anneeActuelle,
    nouvelleAnnee
  });
}

/* ---------- BADGES ---------- */

const badgeKey = (userId) => "badges/" + userId;

async function incrementBadge(s, userId) {
  if (!userId) return 1;
  const key = badgeKey(userId);
  const cur = await s.get(key, { type: "json" });
  const count = (cur?.count || 0) + 1;
  await s.setJSON(key, { count, updatedAt: new Date().toISOString() });
  return count;
}

async function clearBadge(s, userId) {
  if (!userId) return;
  await s.setJSON(badgeKey(userId), { count: 0, updatedAt: new Date().toISOString() });
}

async function deleteBadge(s, userId) {
  if (!userId) return;
  await s.delete(badgeKey(userId));
}

async function clearMyBadge(me, s) {
  await clearBadge(s, me.user.id);
  return json({ ok: true, count: 0 });
}

/* ---------- PUSH NOTIFICATIONS ---------- */

async function pushToMatching(s, payload) {
  if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) return;
  const subs = await listAll(s, "pushsubs/");
  const targets = subs.filter(sub => {
    if (sub.role === "admin") return true;
    if (payload.kind === "communiques") return true;
    if (sub.filiere === payload.filiere && sub.niveau === payload.niveau) return true;
    return false;
  });
  if (!targets.length) return;

  const userIds = [...new Set(targets.map(t => t.userId))];
  const counts = new Map();
  await Promise.all(userIds.map(async (uid) => {
    counts.set(uid, await incrementBadge(s, uid));
  }));

  await Promise.all(targets.map(sub =>
    sendPushToSub(s, sub, { ...payload, badgeCount: counts.get(sub.userId) || 1 })
  ));
}

async function pushToUser(s, userId, payload) {
  if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) return;
  const subs = await listAll(s, "pushsubs/");
  const targets = subs.filter(sub => sub.userId === userId);
  if (!targets.length) return;

  const count = await incrementBadge(s, userId);
  await Promise.all(targets.map(sub =>
    sendPushToSub(s, sub, { ...payload, badgeCount: count })
  ));
}

async function sendPushToSub(s, sub, payload) {
  try {
    const subscription = {
      endpoint: sub.endpoint,
      keys: { p256dh: sub.p256dh, auth: sub.auth }
    };
    await webpush.sendNotification(subscription, JSON.stringify({
      title: payload.title || "INPTIC",
      body: payload.body || "",
      url: payload.url || "/",
      tag: payload.tag || "inptic-" + Date.now(),
      badgeCount: payload.badgeCount || 1
    }));
  } catch (err) {
    if (err.statusCode === 410 || err.statusCode === 404) {
      await s.delete("pushsubs/" + sub.id);
    }
    console.error("Push error:", err.statusCode, err.message);
  }
}

async function subscribePush(req, me, s) {
  const { subscription } = await readJson(req);
  if (!subscription || !subscription.endpoint || !subscription.keys)
    throw new HttpError(400, "Abonnement invalide.");
  const endpoint = subscription.endpoint;
  const id = sha256(endpoint).toString("hex");
  const rec = {
    id,
    userId: me.user.id,
    role: me.role,
    filiere: me.role === "etudiant" ? me.student.filiere : null,
    niveau: me.role === "etudiant" ? me.student.niveau : null,
    endpoint,
    p256dh: subscription.keys.p256dh,
    auth: subscription.keys.auth,
    date: new Date().toISOString()
  };
  await s.setJSON("pushsubs/" + id, rec);
  return json({ ok: true });
}

async function unsubscribePush(req, s) {
  const { endpoint } = await readJson(req);
  if (!endpoint) throw new HttpError(400, "Endpoint requis.");
  const id = sha256(endpoint).toString("hex");
  await s.delete("pushsubs/" + id);
  return json({ ok: true });
}

async function removePushSubsByUser(s, userId) {
  const subs = await listAll(s, "pushsubs/");
  await Promise.all(subs.filter(x => x.userId === userId).map(x => s.delete("pushsubs/" + x.id)));
}

function vapidPublicKey() {
  return json({ publicKey: process.env.VAPID_PUBLIC_KEY || "" });
}

/* ---------- routeur ---------- */

export default async (req) => {
  try {
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 16) {
      throw new HttpError(500, "Configuration serveur incomplète : variable SESSION_SECRET manquante.");
    }
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/api/, "").replace(/\/+$/, "") || "/";
    const seg = path.split("/").filter(Boolean);
    const m = req.method;
    const s = store();

    if (m === "POST" && path === "/login") return await login(req, s);
    if (m === "POST" && path === "/signup") return await signup(req, s);
    if (m === "GET" && path === "/push/vapid-public-key") return vapidPublicKey();
    if (m === "GET" && path === "/locked-years") return await getLockedYearsRoute(s);

    const me = await authenticate(req, s);

    if (m === "GET" && path === "/me") return json({ user: me.user });
    if (m === "POST" && path === "/me/clear-badge") return await clearMyBadge(me, s);
    if (m === "GET" && path === "/data") return await getData(me, s);

    if (m === "POST" && path === "/me/pass") return await passSelf(req, me, s);
    if (m === "POST" && path === "/me/repeat") return await repeatSelf(req, me, s);

    if (m === "POST" && path === "/push/subscribe") return await subscribePush(req, me, s);
    if (m === "POST" && path === "/push/unsubscribe") return await unsubscribePush(req, s);

    if (seg[0] === "admin" && seg[1] === "purge-year" && seg.length === 3) {
      requireAdmin(me);
      if (m === "DELETE") return await purgeYear(s, seg[2]);
    }

    if (seg[0] === "admin" && seg[1] === "purge-communiques" && seg.length === 2) {
      requireAdmin(me);
      if (m === "DELETE") return await purgeCommuniques(s);
    }

    if (seg[0] === "admin" && seg[1] === "lock-year" && seg.length === 3) {
      requireAdmin(me);
      if (m === "POST") return await lockYearRoute(s, seg[2]);
      if (m === "DELETE") return await unlockYearRoute(s, seg[2]);
    }

    if (seg[0] === "students") {
      requireAdmin(me);
      if (m === "POST" && seg.length === 1) return await createStudent(req, s);
      if (m === "PATCH" && seg.length === 2) return await updateStudent(req, s, seg[1]);
      if (m === "DELETE" && seg.length === 2) return await deleteStudent(s, seg[1]);
    }

    if (seg[0] === "docs") {
      if (m === "GET" && seg.length === 3 && seg[2] === "file") return await downloadDoc(req, me, s, seg[1], url);
      requireAdmin(me);
      if (m === "POST" && seg.length === 1) return await uploadDoc(req, s, url);
      if (m === "DELETE" && seg.length === 2) return await deleteDoc(s, seg[1]);
    }

    throw new HttpError(404, "Route inconnue.");
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: "Erreur serveur." }, 500);
  }
};

export const config = { path: "/api/*" };