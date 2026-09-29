const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "inptic-secret-change-en-prod";

const db = new Database("campus.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, nom TEXT, prenom TEXT, filiere TEXT, niveau TEXT,
    email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'etudiant', created_at TEXT
  );
  CREATE TABLE IF NOT EXISTS docs (
    id TEXT PRIMARY KEY, kind TEXT, filiere TEXT, niveau TEXT, titre TEXT,
    nom_fichier TEXT, taille INTEGER, date_ajout TEXT, data BLOB
  );
`);

if(!db.prepare("SELECT id FROM users WHERE role='admin'").get()){
  const hash = bcrypt.hashSync("admin123", 10);
  db.prepare(`INSERT INTO users (id,nom,prenom,filiere,niveau,email,password,role,created_at)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(
    "admin-1","Admin","INPTIC","GI","L1","admin@inptic.ga",hash,"admin",new Date().toISOString()
  );
  console.log("✅ Admin créé : admin@inptic.ga / admin123");
}

app.use(cors());
app.use(express.json({ limit: "10mb" }));

// Route explicite pour la page d'accueil (le dossier public/ est dans le parent)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "index.html"));
});

// Fichiers statiques (sw.js, manifest.json, images, etc.)
app.use(express.static(path.join(__dirname, "..", "public")));

function auth(req,res,next){
  const h = req.headers.authorization;
  if(!h || !h.startsWith("Bearer ")) return res.status(401).json({error:"Non authentifié"});
  try{ req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch(e){ res.status(401).json({error:"Token invalide"}); }
}
function adminOnly(req,res,next){
  if(req.user.role !== "admin") return res.status(403).json({error:"Réservé à l'admin"});
  next();
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5*1024*1024 } });

app.post("/api/login", (req,res)=>{
  const { email, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({error:"Identifiants invalides"});
  const token = jwt.sign({id:user.id, role:user.role}, JWT_SECRET, {expiresIn:"7d"});
  res.json({ token, user:{id:user.id, nom:user.nom, prenom:user.prenom, filiere:user.filiere, niveau:user.niveau, role:user.role, email:user.email} });
});

app.post("/api/signup", (req,res)=>{
  const { nom, prenom, filiere, niveau, email, password } = req.body || {};
  if(!nom||!prenom||!filiere||!niveau||!email||!password)
    return res.status(400).json({error:"Champs manquants"});
  if(db.prepare("SELECT id FROM users WHERE email=?").get(email))
    return res.status(409).json({error:"Cet e-mail est déjà utilisé"});
  const id = "u-" + Date.now().toString(36);
  const hash = bcrypt.hashSync(password, 10);
  db.prepare(`INSERT INTO users (id,nom,prenom,filiere,niveau,email,password,role,created_at)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(id,nom,prenom,filiere,niveau,email,hash,"etudiant",new Date().toISOString());
  const token = jwt.sign({id, role:"etudiant"}, JWT_SECRET, {expiresIn:"7d"});
  res.json({ token, user:{id,nom,prenom,filiere,niveau,email,role:"etudiant"} });
});

app.get("/api/me", auth, (req,res)=>{
  const u = db.prepare("SELECT id,nom,prenom,filiere,niveau,email,role FROM users WHERE id=?").get(req.user.id);
  res.json({ user:u });
});

app.get("/api/data", auth, (req,res)=>{
  const students = db.prepare("SELECT id,nom,prenom,filiere,niveau,email FROM users WHERE role='etudiant'").all();
  const docs = db.prepare("SELECT id,kind,filiere,niveau,titre,nom_fichier AS nomFichier,taille,date_ajout AS dateAjout FROM docs").all();
  res.json({ students, docs });
});

app.post("/api/students", auth, adminOnly, (req,res)=>{
  const { nom, prenom, filiere, niveau, email } = req.body;
  const id = "u-" + Date.now().toString(36);
  const hash = bcrypt.hashSync("etudiant123", 10);
  db.prepare(`INSERT INTO users (id,nom,prenom,filiere,niveau,email,password,role,created_at)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(id,nom,prenom,filiere,niveau,email,hash,"etudiant",new Date().toISOString());
  res.json({ id });
});

app.patch("/api/students/:id", auth, adminOnly, (req,res)=>{
  const { nom, prenom, filiere, niveau, email } = req.body;
  db.prepare("UPDATE users SET nom=?,prenom=?,filiere=?,niveau=?,email=? WHERE id=?")
    .run(nom,prenom,filiere,niveau,email,req.params.id);
  res.json({ ok:true });
});

app.delete("/api/students/:id", auth, adminOnly, (req,res)=>{
  db.prepare("DELETE FROM users WHERE id=?").run(req.params.id);
  res.json({ ok:true });
});

// ✅ CORRIGÉ : Gestion complète des erreurs d'upload
app.post("/api/docs", auth, adminOnly, (req, res) => {
  upload.single("file")(req, res, (err) => {
    // Gestion des erreurs Multer (fichier trop gros, mauvais champ, etc.)
    if (err) {
      console.error("❌ Erreur Multer:", err.message);
      return res.status(500).json({ error: "Erreur upload: " + err.message });
    }

    // ✅ CORRIGÉ : Vérifier que le fichier est bien présent
    if (!req.file) {
      console.error("❌ Aucun fichier reçu. Vérifiez le nom du champ dans le frontend.");
      return res.status(400).json({ error: "Aucun fichier reçu. Le champ doit s'appeler 'file'." });
    }

    // ✅ CORRIGÉ : Les données sont dans req.body (pas req.query)
    // On accepte les deux au cas où (body OU query), pour être sûr.
    const kind    = req.body.kind    || req.query.kind;
    const filiere = req.body.filiere || req.query.filiere;
    const niveau  = req.body.niveau  || req.query.niveau;
    const titre   = req.body.titre   || req.query.titre;
    // Le nom du fichier : on prend celui envoyé dans le form, sinon le nom original du fichier
    const nom     = req.body.nom     || req.query.nom || req.file.originalname;

    // Vérification des champs obligatoires
    if (!kind || !filiere || !niveau) {
      console.error("❌ Champs manquants:", { kind, filiere, niveau });
      return res.status(400).json({ error: "Champs 'kind', 'filiere' et 'niveau' obligatoires." });
    }

    try {
      const id = "d-" + Date.now().toString(36);
      db.prepare(`INSERT INTO docs (id,kind,filiere,niveau,titre,nom_fichier,taille,date_ajout,data)
        VALUES (?,?,?,?,?,?,?,?,?)`).run(
          id, kind, filiere, niveau, titre, nom,
          req.file.size, new Date().toISOString(), req.file.buffer
        );
      console.log("✅ PDF enregistré:", id, nom);
      res.json({ id });
    } catch (dbErr) {
      console.error("❌ Erreur DB:", dbErr.message);
      res.status(500).json({ error: "Erreur base de données: " + dbErr.message });
    }
  });
});

app.get("/api/docs/:id/file", auth, (req,res)=>{
  const d = db.prepare("SELECT nom_fichier, data FROM docs WHERE id=?").get(req.params.id);
  if(!d) return res.status(404).json({error:"Introuvable"});
  res.set("Content-Type","application/pdf");
  res.set("Content-Disposition", `inline; filename="${d.nom_fichier}"`);
  res.send(d.data);
});

app.delete("/api/docs/:id", auth, adminOnly, (req,res)=>{
  db.prepare("DELETE FROM docs WHERE id=?").run(req.params.id);
  res.json({ ok:true });
});

app.listen(PORT, ()=> console.log(`✅ Backend sur http://localhost:${PORT}`));