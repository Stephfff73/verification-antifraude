"""
verif_conformite.py
Contrôle automatique : le document déposé correspond-il bien à la pièce demandée ?

Principe :
  1. Chaque champ de dépôt (ex. "fiche_paie_2") a un type attendu.
  2. Le texte extrait (PDF ou OCR) est comparé à des "signatures" (mots-clés
     pondérés) de chaque type de document.
  3. Verdict par document : conforme / à vérifier / non conforme.
  4. Contrôles croisés : 3 fiches de paie sur 3 mois distincts et consécutifs,
     même employeur, 3 quittances idem, pièce d'identité présente.
"""

import re
import unicodedata
from collections import Counter
from datetime import datetime

import pandas as pd
import streamlit as st

# ----------------------------------------------------------------------
# Paramètres
# ----------------------------------------------------------------------
SCORE_MIN = 4            # score minimal pour considérer un type "reconnu"
TOLERANCE = 0.7          # le type attendu doit valoir >= 70 % du meilleur score
ANCIENNETE_MAX_MOIS = 4  # une fiche/quittance plus vieille que ça est signalée
TEXTE_MIN = 30           # en dessous : texte jugé inexploitable

MOIS = {
    'janvier': 1, 'fevrier': 2, 'mars': 3, 'avril': 4, 'mai': 5, 'juin': 6,
    'juillet': 7, 'aout': 8, 'septembre': 9, 'octobre': 10,
    'novembre': 11, 'decembre': 12,
}
_MOIS_RE = '|'.join(MOIS.keys())

LABELS = {
    'carte_identite': "Carte d'identité",
    'passeport': "Passeport",
    'titre_sejour': "Titre de séjour",
    'permis_conduire': "Permis de conduire",
    'contrat_travail': "Contrat de travail",
    'fiche_paie': "Fiche de paie",
    'avis_imposition': "Avis d'imposition",
    'quittance': "Quittance de loyer",
    'facture': "Facture (énergie / internet)",
}

FAMILLE = {
    'carte_identite': 'identite', 'passeport': 'identite',
    'titre_sejour': 'identite', 'permis_conduire': 'identite',
    'contrat_travail': 'contrat', 'fiche_paie': 'paie',
    'avis_imposition': 'avis', 'quittance': 'domicile', 'facture': 'domicile',
}

# (regex sur texte normalisé : minuscules, sans accents, apostrophes droites ; poids)
SIGNATURES = {
    'carte_identite': [
        (r"carte nationale d'? ?identite", 4), (r"carte nationale", 3),
        (r"\bidfra", 4), (r"republique francaise", 1),
        (r"nationalite francaise", 2), (r"\bprenoms?\b|\bprenom\(s\)", 1),
        (r"date de naissance", 1), (r"lieu de naissance", 1),
        (r"\bsexe\b", 1), (r"signature du titulaire", 2),
    ],
    'passeport': [
        (r"\bpasseport\b|\bpassport\b", 4), (r"p<fra", 5),
        (r"code du pays|country code", 2), (r"autorite|authority", 1),
    ],
    'titre_sejour': [
        (r"titre de sejour", 5), (r"carte de sejour", 5),
        (r"residence permit", 3), (r"\bofii\b", 2),
        (r"type de titre", 2), (r"\bsejour\b", 2), (r"ministere de l'interieur", 1),
    ],
    'permis_conduire': [
        (r"permis de conduire", 5), (r"driving licen[cs]e", 4),
        (r"\bconduire\b", 2), (r"\bprefet\b|prefecture", 1), (r"categories?", 1),
    ],
    'contrat_travail': [
        (r"contrat de travail", 5), (r"entre les soussignes", 3),
        (r"\bcdi\b", 2), (r"\bcdd\b", 2),
        (r"duree indeterminee|duree determinee", 3), (r"\bemployeur\b", 2),
        (r"\bsalarie", 1), (r"periode d'essai", 3), (r"lieu de travail", 2),
        (r"en qualite de|fonctions? de", 1), (r"convention collective", 1),
        (r"duree du travail", 1), (r"remuneration", 1),
    ],
    'fiche_paie': [
        (r"bulletin de (paie|salaire)", 5), (r"net a payer", 4),
        (r"net imposable", 3), (r"salaire brut", 2), (r"\bbrut\b", 1),
        (r"cotisations?", 2), (r"urssaf", 2), (r"conges payes", 2),
        (r"prelevement a la source", 2), (r"\bcsg\b|\bcrds\b", 2),
        (r"\bmatricule\b", 1), (r"\bsiret\b", 1), (r"retraite", 1),
    ],
    'avis_imposition': [
        (r"avis d'? ?(impot|imposition)", 5), (r"revenu fiscal de reference", 5),
        (r"numero fiscal", 3),
        (r"direction generale des finances publiques|\bdgfip\b", 3),
        (r"impots\.gouv", 2), (r"nombre de parts", 3),
        (r"impot sur le revenu", 2), (r"declarant", 2),
        (r"revenu imposable", 2), (r"avis de situation declarative", 3),
    ],
    'quittance': [
        (r"quittance", 5), (r"\bloyer\b", 2), (r"locataire", 2),
        (r"bailleur|proprietaire", 2), (r"declare avoir recu|je soussigne", 2),
        (r"\bbail\b", 1), (r"\bcharges\b", 1), (r"echeance", 1),
    ],
    'facture': [
        (r"\bfacture\b", 3), (r"n° ?de facture|numero de facture", 3),
        (r"\bttc\b", 2), (r"\btva\b", 1),
        (r"\bedf\b|engie|totalenergies|enedis|veolia|orange|\bsfr\b|bouygues|\bfree\b|\bsosh\b", 2),
        (r"electricite|\bgaz\b|internet|fibre|forfait mobile|abonnement", 2),
        (r"consommation|\bkwh\b|point de livraison|\bpdl\b|\bpce\b", 2),
        (r"reference client|numero client", 2),
    ],
}


# ----------------------------------------------------------------------
# Utilitaires
# ----------------------------------------------------------------------
def _norm(texte: str) -> str:
    t = unicodedata.normalize('NFKD', texte or '')
    t = ''.join(c for c in t if not unicodedata.combining(c)).lower()
    t = t.replace('’', "'").replace('`', "'")
    return re.sub(r'\s+', ' ', t)


def type_attendu(doc_key: str):
    """Déduit le type attendu à partir de la clé du champ de dépôt."""
    for prefixe, typ in [
        ('carte_identite', 'carte_identite'), ('permis_conduire', 'permis_conduire'),
        ('passeport', 'passeport'), ('titre_sejour', 'titre_sejour'),
        ('contrat_travail', 'contrat_travail'), ('fiche_paie', 'fiche_paie'),
        ('avis_imposition', 'avis_imposition'), ('quittance', 'quittance'),
        ('facture', 'facture'),
    ]:
        if doc_key.startswith(prefixe):
            return typ
    return None


def scorer(texte_norm: str) -> dict:
    return {
        cat: sum(w for pat, w in sigs if re.search(pat, texte_norm))
        for cat, sigs in SIGNATURES.items()
    }


def extraire_periode(texte_norm: str):
    """Retourne (année, mois) de la période du document, ou None."""
    m = re.search(
        r"du (\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4}) au (\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4})",
        texte_norm)
    if m and 1 <= int(m.group(5)) <= 12:
        return int(m.group(6)), int(m.group(5))

    m = re.search(r"periode.{0,40}?(" + _MOIS_RE + r")\s+(20\d{2})", texte_norm)
    if m:
        return int(m.group(2)), MOIS[m.group(1)]

    trouves = [(int(y), MOIS[mo]) for mo, y in
               re.findall(r"\b(" + _MOIS_RE + r")\s+(20\d{2})\b", texte_norm)]
    if trouves:
        return Counter(trouves).most_common(1)[0][0]

    trouves = [(int(y), int(mo)) for mo, y in
               re.findall(r"\b(0[1-9]|1[0-2])[/.\-](20\d{2})\b", texte_norm)]
    if trouves:
        return Counter(trouves).most_common(1)[0][0]
    return None


def extraire_siret(texte: str):
    m = re.search(r"siret\D{0,10}((?:\d[\s.]?){14})", texte or '', re.IGNORECASE)
    return re.sub(r'\D', '', m.group(1)) if m else None


# ----------------------------------------------------------------------
# Contrôle d'un document
# ----------------------------------------------------------------------
def verifier_document(doc_key: str, texte: str) -> dict:
    attendu = type_attendu(doc_key)
    res = {
        'doc_key': doc_key,
        'attendu': attendu,
        'attendu_label': LABELS.get(attendu, doc_key),
        'detecte': None,
        'detecte_label': 'Indéterminé',
        'confiance': 0,
        'statut': 'a_verifier',
        'message': '',
        'scores': {},
        'periode': None,
    }
    texte = texte or ''
    t = _norm(texte)

    # Texte inexploitable (message d'erreur d'extraction inclus)
    if len(t) < TEXTE_MIN or t.startswith(('erreur', '⚠', '❌')):
        res['message'] = ("Texte non exploitable (scan illisible, PDF image ou OCR indisponible) "
                          "→ contrôle manuel nécessaire.")
        return res

    scores = scorer(t)
    res['scores'] = scores
    classes = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    meilleur, s1 = classes[0]
    s2 = classes[1][1]

    if s1 < SCORE_MIN:
        res['message'] = "Aucun marqueur caractéristique d'un type de document reconnu → contrôle manuel."
        return res

    res['detecte'] = meilleur
    res['detecte_label'] = LABELS[meilleur]
    res['confiance'] = int(round(100 * (s1 / (s1 + s2)) * min(1.0, s1 / 8)))

    s_attendu = scores.get(attendu, 0)
    if attendu and s_attendu >= SCORE_MIN and s_attendu >= TOLERANCE * s1:
        res['statut'] = 'conforme'
        res['message'] = f"Document reconnu comme : {LABELS[attendu]}."
    elif attendu and FAMILLE.get(meilleur) == FAMILLE.get(attendu):
        res['statut'] = 'a_verifier'
        res['message'] = (f"Pièce de la bonne catégorie mais type différent : "
                          f"détecté « {LABELS[meilleur]} » dans le champ « {LABELS[attendu]} ».")
    else:
        res['statut'] = 'non_conforme'
        res['message'] = (f"Le document ressemble à « {LABELS[meilleur]} » "
                          f"alors que « {LABELS.get(attendu, doc_key)} » est attendu.")

    if attendu in ('fiche_paie', 'quittance', 'facture') and res['statut'] != 'non_conforme':
        res['periode'] = extraire_periode(t)
    return res


# ----------------------------------------------------------------------
# Contrôles croisés
# ----------------------------------------------------------------------
def _idx(p):
    return p[0] * 12 + p[1]


def _controle_series(docs: dict, prefixe: str, libelle: str, attendus: int, alertes: list):
    cles = sorted(k for k in docs if k.startswith(prefixe))
    if not cles:
        return []
    periodes = []
    for k in cles:
        p = docs[k].get('periode')
        if p:
            periodes.append((k, p))
        elif docs[k]['statut'] == 'conforme':
            alertes.append({'niveau': 'info',
                            'message': f"{libelle} « {k} » : période non détectée, à vérifier manuellement."})

    if len(cles) < attendus:
        alertes.append({'niveau': 'info',
                        'message': f"{libelle} : {len(cles)}/{attendus} document(s) fourni(s)."})

    vus = Counter(p for _, p in periodes)
    for p, n in vus.items():
        if n > 1:
            alertes.append({'niveau': 'warning',
                            'message': f"{libelle} : {n} documents portent la même période "
                                       f"({p[1]:02d}/{p[0]}) – doublon possible."})

    distinctes = sorted(set(p for _, p in periodes), key=_idx)
    if len(distinctes) >= 2:
        if any(_idx(b) - _idx(a) != 1 for a, b in zip(distinctes, distinctes[1:])):
            txt = ', '.join(f"{m:02d}/{a}" for a, m in distinctes)
            alertes.append({'niveau': 'warning',
                            'message': f"{libelle} : périodes non consécutives ({txt})."})
    if distinctes:
        now = datetime.now()
        retard = (now.year * 12 + now.month) - _idx(distinctes[-1])
        if retard > ANCIENNETE_MAX_MOIS:
            a, m = distinctes[-1]
            alertes.append({'niveau': 'warning',
                            'message': f"{libelle} : le plus récent date de {m:02d}/{a} "
                                       f"(> {ANCIENNETE_MAX_MOIS} mois)."})
    return cles


def controles_croises(documents_data: dict, resultats: dict) -> list:
    alertes = []

    # 1. Pièce d'identité
    identite = [r for k, r in resultats.items() if FAMILLE.get(r['attendu']) == 'identite']
    if not identite:
        alertes.append({'niveau': 'warning', 'message': "Aucune pièce d'identité déposée."})
    elif not any(r['statut'] == 'conforme' for r in identite):
        alertes.append({'niveau': 'warning',
                        'message': "Aucune pièce d'identité n'a pu être validée automatiquement."})
    if 'carte_identite_recto' in resultats and 'carte_identite_verso' not in resultats:
        alertes.append({'niveau': 'info', 'message': "Carte d'identité : verso manquant."})
    if 'carte_identite_verso' in resultats and 'carte_identite_recto' not in resultats:
        alertes.append({'niveau': 'info', 'message': "Carte d'identité : recto manquant."})

    # 2. Séries mensuelles
    cles_paie = _controle_series(resultats, 'fiche_paie', 'Fiches de paie', 3, alertes)
    has_fact = any(k.startswith('facture') for k in resultats)
    _controle_series(resultats, 'quittance', 'Quittances de loyer',
                     3 if not has_fact else 1, alertes)

    # 3. Même employeur sur les fiches de paie
    sirets = {}
    for k in cles_paie:
        txt = (documents_data.get(k, {}).get('text_full')
               or documents_data.get(k, {}).get('text_extract') or '')
        s = extraire_siret(txt)
        if s:
            sirets[k] = s
    if len(set(sirets.values())) > 1:
        detail = ', '.join(f"{k}: {v}" for k, v in sirets.items())
        alertes.append({'niveau': 'warning',
                        'message': f"Fiches de paie : SIRET différents d'un bulletin à l'autre ({detail})."})

    # 4. Pièces clés absentes
    for cle, lib in [('contrat_travail', 'Contrat de travail'),
                     ('avis_imposition', "Avis d'imposition")]:
        if cle not in resultats:
            alertes.append({'niveau': 'info', 'message': f"{lib} non déposé."})
    if not any(FAMILLE.get(r['attendu']) == 'domicile' for r in resultats.values()):
        alertes.append({'niveau': 'info', 'message': "Aucun justificatif de domicile déposé."})
    return alertes


# ----------------------------------------------------------------------
# Point d'entrée
# ----------------------------------------------------------------------
def verifier_conformite_dossier(documents_data: dict) -> dict:
    """documents_data = results['documents'] de analyze_all_documents()."""
    resultats = {}
    for key, doc in documents_data.items():
        texte = doc.get('text_full') or doc.get('text_extract') or ''
        resultats[key] = verifier_document(key, texte)

    croises = controles_croises(documents_data, resultats)
    n = len(resultats)
    c = Counter(r['statut'] for r in resultats.values())
    if c['non_conforme']:
        decision = 'NON_CONFORME'
    elif c['a_verifier'] or any(a['niveau'] == 'warning' for a in croises):
        decision = 'A_VERIFIER'
    else:
        decision = 'OK'
    return {
        'documents': resultats,
        'croises': croises,
        'synthese': {
            'total': n,
            'conforme': c['conforme'],
            'a_verifier': c['a_verifier'],
            'non_conforme': c['non_conforme'],
            'taux_conformite': round(100 * c['conforme'] / n) if n else 0,
        },
        'decision': decision,
    }


def conformite_to_dataframe(conf: dict) -> pd.DataFrame:
    icones = {'conforme': '✅ Conforme', 'a_verifier': '⚠️ À vérifier', 'non_conforme': '❌ Non conforme'}
    lignes = []
    for key, r in conf.get('documents', {}).items():
        p = r.get('periode')
        lignes.append({
            'Champ de dépôt': key.replace('_', ' ').title(),
            'Pièce attendue': r['attendu_label'],
            'Pièce détectée': r['detecte_label'],
            'Confiance': f"{r['confiance']}%",
            'Période détectée': f"{p[1]:02d}/{p[0]}" if p else '',
            'Statut': icones[r['statut']],
            'Commentaire': r['message'],
        })
    return pd.DataFrame(lignes)


# ----------------------------------------------------------------------
# Affichage Streamlit
# ----------------------------------------------------------------------
def afficher_conformite(analysis_results: dict):
    st.markdown("## ✅ Conformité des pièces déposées")
    conf = (analysis_results or {}).get('conformite')
    if not conf:
        st.warning("⚠️ Lancez d'abord l'analyse des documents.")
        return

    s = conf['synthese']
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Documents contrôlés", s['total'])
    c2.metric("✅ Conformes", s['conforme'])
    c3.metric("⚠️ À vérifier", s['a_verifier'])
    c4.metric("❌ Non conformes", s['non_conforme'])

    decision = conf['decision']
    if decision == 'OK':
        st.markdown('<div class="alert-box alert-success"><h4>✅ Toutes les pièces correspondent '
                    'à ce qui est attendu</h4></div>', unsafe_allow_html=True)
    elif decision == 'A_VERIFIER':
        st.markdown('<div class="alert-box alert-warning"><h4>⚠️ Quelques points à vérifier '
                    'manuellement</h4></div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="alert-box alert-critical"><h4>❌ Au moins une pièce ne correspond '
                    'pas au document attendu</h4></div>', unsafe_allow_html=True)

    st.markdown("### 📋 Détail par document")
    st.dataframe(conformite_to_dataframe(conf), use_container_width=True, hide_index=True)

    if conf['croises']:
        st.markdown("### 🔄 Contrôles croisés")
        for a in conf['croises']:
            classe = 'alert-warning' if a['niveau'] == 'warning' else 'info-box'
            ico = '⚠️' if a['niveau'] == 'warning' else 'ℹ️'
            st.markdown(f'<div class="alert-box {classe}">{ico} {a["message"]}</div>',
                        unsafe_allow_html=True)

    with st.expander("🔬 Scores de reconnaissance par type (diagnostic)"):
        for key, r in conf['documents'].items():
            if r['scores']:
                top = sorted(r['scores'].items(), key=lambda x: x[1], reverse=True)[:4]
                st.write(f"**{key}** : " + " | ".join(f"{LABELS[k]} = {v}" for k, v in top))
            else:
                st.write(f"**{key}** : pas de score (texte non exploitable)")
