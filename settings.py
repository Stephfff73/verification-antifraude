"""
Configuration et paramètres de l'application anti-fraude
"""

# Seuils de détection de fraude (0-1)
FRAUD_THRESHOLDS = {
    'metadata_manipulation': 0.3,
    'image_ela_score': 0.15,
    'text_inconsistency': 0.25,
    'cross_validation': 0.20
}

# Poids pour le calcul du score global
DOCUMENT_WEIGHTS = {
    'contrat_travail': 0.20,
    'fiche_paie': 0.30,
    'avis_imposition': 0.20,
    'piece_identite': 0.15,
    'quittance_loyer': 0.10,
    'caf': 0.05
}

# Types de documents acceptés
ALLOWED_EXTENSIONS = ['pdf', 'jpg', 'jpeg', 'png', 'tiff']
MAX_FILE_SIZE_MB = 10

# Paramètres OCR
OCR_CONFIG = {
    'lang': 'fra',
    'dpi': 300,
    'psm': 3  # Page Segmentation Mode (3 = Automatic)
}

# Clauses obligatoires par type de document
MANDATORY_CLAUSES = {
    'contrat_travail': [
        'fonction',
        'rémunération',
        'lieu de travail',
        'durée du travail',
        'période d\'essai'
    ],
    'fiche_paie': [
        'siret',
        'urssaf',
        'brut',
        'net',
        'cotisations'
    ],
    'avis_imposition': [
        'numéro fiscal',
        'dgfip',
        'revenus',
        'impôt'
    ]
}

# Patterns regex pour extraction
REGEX_PATTERNS = {
    'siret': r'\b\d{14}\b',
    'numero_fiscal': r'\b\d{13}\b',
    'date_fr': r'\b\d{2}/\d{2}/\d{4}\b',
    'montant_euro': r'(\d+[\s,]?\d*)\s*€',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'telephone': r'\b0[1-9](?:\s?\d{2}){4}\b'
}

# Niveaux de verdict
VERDICT_LEVELS = {
    'fiable': {
        'range': (0, 20),
        'label': '✅ DOSSIER FIABLE',
        'color': '#10b981',
        'recommendation': 'Validation recommandée'
    },
    'vigilance': {
        'range': (20, 40),
        'label': '⚠️ VIGILANCE RECOMMANDÉE',
        'color': '#f59e0b',
        'recommendation': 'Vérifications complémentaires nécessaires'
    },
    'suspicion': {
        'range': (40, 70),
        'label': '🔴 SUSPICION DE FRAUDE',
        'color': '#ef4444',
        'recommendation': 'Refus recommandé - Investigation approfondie requise'
    },
    'fraude': {
        'range': (70, 100),
        'label': '🚨 FRAUDE PROBABLE',
        'color': '#991b1b',
        'recommendation': 'Refus immédiat - Signalement aux autorités'
    }
}

# Messages d'aide
HELP_MESSAGES = {
    'contrat_travail': "Contrat de travail CDI/CDD avec signature employeur et salarié",
    'fiche_paie': "3 dernières fiches de paie consécutives (max 4 mois d'ancienneté)",
    'avis_imposition': "Dernier avis d'imposition complet avec numéro fiscal",
    'piece_identite': "Carte d'identité ou passeport en cours de validité",
    'quittance_loyer': "3 dernières quittances de loyer ou attestation propriétaire",
    'caf': "Attestation de paiement CAF (APL/ALF) si applicable"
}
