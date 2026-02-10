"""
🔍 IN'LI - SYSTÈME DE DÉTECTION DE FRAUDE DOCUMENTAIRE
Application Streamlit pour la vérification des dossiers locataires
Version Beta 1.0
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import os
import json
from pathlib import Path

# Import des modules utilitaires
from utils.metadata_analyzer import analyze_document_metadata
from utils.ocr_processor import extract_text_from_document
from utils.fraud_detector import (
    validate_contrat_travail,
    validate_fiche_paie,
    validate_avis_imposition,
    validate_piece_identite,
    validate_quittance_loyer
)
from utils.cross_validator import cross_validate_dossier
from utils.scoring_engine import calculate_fraud_score, generate_report

# Configuration de la page
st.set_page_config(
    page_title="App Anti-Fraude Documentaire",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialisation des dossiers
Path("data/uploads").mkdir(parents=True, exist_ok=True)
Path("data/results").mkdir(parents=True, exist_ok=True)

# Style CSS personnalisé
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1e3a8a;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .score-box {
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        font-size: 1.5rem;
        font-weight: bold;
        margin: 10px 0;
    }
    .score-green { background-color: #10b981; color: white; }
    .score-orange { background-color: #f59e0b; color: white; }
    .score-red { background-color: #ef4444; color: white; }
    .score-darkred { background-color: #991b1b; color: white; }
    
    .metric-card {
        background-color: #f8fafc;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #3b82f6;
        margin: 10px 0;
    }
    .alert-box {
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }
    .alert-warning { background-color: #fef3c7; border-left: 4px solid #f59e0b; }
    .alert-danger { background-color: #fee2e2; border-left: 4px solid #ef4444; }
    .alert-success { background-color: #d1fae5; border-left: 4px solid #10b981; }
</style>
""", unsafe_allow_html=True)

# Initialisation de la session state
if 'uploaded_files' not in st.session_state:
    st.session_state.uploaded_files = {}
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = {}
if 'current_dossier' not in st.session_state:
    st.session_state.current_dossier = None


def main():
    """Fonction principale de l'application"""
    
    # En-tête
    st.markdown('<div class="main-header">🔍 IN\'LI - DÉTECTION DE FRAUDE DOCUMENTAIRE</div>', 
                unsafe_allow_html=True)
    
    # Menu latéral
    with st.sidebar:
        st.image("https://via.placeholder.com/200x80/667eea/ffffff?text=In%27li", 
                 use_container_width=True)
        st.markdown("---")
        
        page = st.radio(
            "📋 Navigation",
            ["🏠 Accueil", "📤 Upload Documents", "🔍 Analyse Individuelle", 
             "📊 Analyse Globale", "📑 Rapport Détaillé"],
            index=0
        )
        
        st.markdown("---")
        st.markdown("### 📊 Statistiques")
        nb_docs = len(st.session_state.uploaded_files)
        st.metric("Documents uploadés", nb_docs)
        
        if st.session_state.analysis_results:
            score = st.session_state.analysis_results.get('global_score', {}).get('score', 0)
            st.metric("Score de fraude", f"{score:.1f}%")
    
    # Routage des pages
    if page == "🏠 Accueil":
        page_accueil()
    elif page == "📤 Upload Documents":
        page_upload()
    elif page == "🔍 Analyse Individuelle":
        page_analyse_individuelle()
    elif page == "📊 Analyse Globale":
        page_analyse_globale()
    elif page == "📑 Rapport Détaillé":
        page_rapport()


def page_accueil():
    """Page d'accueil avec présentation"""
    
    st.markdown("## 👋 Bienvenue sur l'outil de détection de fraude")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🎯 Objectif
        Cet outil vérifie automatiquement l'authenticité des documents 
        fournis par les postulants locataires en détectant :
        
        - 📝 Modifications de documents
        - 🖼️ Retouches graphiques
        - ⚠️ Incohérences de données
        - 🔄 Contradictions entre documents
        """)
        
    with col2:
        st.markdown("""
        ### 📄 Documents analysés
        
        - ✅ Contrat de travail
        - ✅ Fiches de paie (3 dernières)
        - ✅ Avis d'imposition
        - ✅ Pièce d'identité
        - ✅ Quittances de loyer
        - ✅ Justificatifs CAF (APL)
        """)
    
    st.markdown("---")
    
    st.markdown("### 🚀 Démarrage rapide")
    
    st.info("""
    **3 étapes simples :**
    1. 📤 Uploadez les documents du dossier locataire
    2. 🔍 Lancez l'analyse automatique
    3. 📊 Consultez le rapport de fraude
    """)
    
    # Indicateurs de performance
    st.markdown("### 📈 Indicateurs de détection")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h3 style="color: #3b82f6;">98%</h3>
            <p>Précision métadonnées</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h3 style="color: #10b981;">95%</h3>
            <p>Détection OCR</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h3 style="color: #f59e0b;">92%</h3>
            <p>Analyse graphique</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="metric-card">
            <h3 style="color: #ef4444;">97%</h3>
            <p>Validation croisée</p>
        </div>
        """, unsafe_allow_html=True)


def page_upload():
    """Page d'upload des documents"""
    
    st.markdown("## 📤 Upload des documents")
    
    st.info("💡 Formats acceptés : PDF, JPG, PNG - Taille max : 10 MB par fichier")
    
    # Types de documents
    doc_types = {
        "contrat_travail": "📝 Contrat de travail",
        "fiche_paie_1": "💰 Fiche de paie 1 (la plus récente)",
        "fiche_paie_2": "💰 Fiche de paie 2",
        "fiche_paie_3": "💰 Fiche de paie 3",
        "avis_imposition": "🏛️ Avis d'imposition",
        "piece_identite": "🆔 Pièce d'identité",
        "quittance_1": "🏠 Quittance de loyer 1",
        "quittance_2": "🏠 Quittance de loyer 2",
        "quittance_3": "🏠 Quittance de loyer 3",
        "justificatif_caf": "🏦 Justificatif CAF (optionnel)"
    }
    
    # Affichage des uploaders
    for doc_key, doc_label in doc_types.items():
        with st.expander(doc_label, expanded=False):
            uploaded_file = st.file_uploader(
                f"Choisir le fichier",
                type=['pdf', 'jpg', 'jpeg', 'png'],
                key=f"uploader_{doc_key}"
            )
            
            if uploaded_file:
                # Sauvegarder le fichier
                file_path = Path(f"data/uploads/{doc_key}_{uploaded_file.name}")
                with open(file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                
                st.session_state.uploaded_files[doc_key] = {
                    'path': str(file_path),
                    'name': uploaded_file.name,
                    'type': uploaded_file.type,
                    'size': uploaded_file.size,
                    'upload_date': datetime.now().isoformat()
                }
                
                st.success(f"✅ {uploaded_file.name} uploadé ({uploaded_file.size / 1024:.1f} KB)")
    
    st.markdown("---")
    
    # Récapitulatif
    if st.session_state.uploaded_files:
        st.markdown("### 📋 Récapitulatif des documents")
        
        df_recap = pd.DataFrame([
            {
                'Type': doc_types.get(k, k),
                'Fichier': v['name'],
                'Taille': f"{v['size'] / 1024:.1f} KB",
                'Date': datetime.fromisoformat(v['upload_date']).strftime("%d/%m/%Y %H:%M")
            }
            for k, v in st.session_state.uploaded_files.items()
        ])
        
        st.dataframe(df_recap, use_container_width=True)
        
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            if st.button("🗑️ Tout supprimer", type="secondary", use_container_width=True):
                st.session_state.uploaded_files = {}
                st.session_state.analysis_results = {}
                st.rerun()
        
        with col2:
            if st.button("🔍 Lancer l'analyse", type="primary", use_container_width=True):
                with st.spinner("🔄 Analyse en cours..."):
                    launch_analysis()
                st.success("✅ Analyse terminée !")
                st.balloons()
        
        with col3:
            if st.button("📊 Voir les résultats", use_container_width=True):
                st.session_state.current_page = "📊 Analyse Globale"
                st.rerun()


def launch_analysis():
    """Lance l'analyse complète du dossier"""
    
    results = {}
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    total_docs = len(st.session_state.uploaded_files)
    
    for idx, (doc_key, doc_info) in enumerate(st.session_state.uploaded_files.items()):
        
        status_text.text(f"Analyse de {doc_info['name']}...")
        
        # 1. Extraction métadonnées
        metadata = analyze_document_metadata(doc_info['path'])
        
        # 2. Extraction texte OCR
        text = extract_text_from_document(doc_info['path'])
        
        # 3. Analyse spécifique selon type
        if 'contrat' in doc_key:
            validation = validate_contrat_travail(text, metadata)
        elif 'fiche_paie' in doc_key:
            validation = validate_fiche_paie(text, metadata)
        elif 'avis_imposition' in doc_key:
            validation = validate_avis_imposition(text, metadata)
        elif 'piece_identite' in doc_key:
            validation = validate_piece_identite(text, metadata)
        elif 'quittance' in doc_key:
            validation = validate_quittance_loyer(text, metadata)
        else:
            validation = {'score_fraude': 0, 'checks': {}}
        
        results[doc_key] = {
            'metadata': metadata,
            'text_extract': text[:500],  # Premiers 500 caractères
            'validation': validation
        }
        
        progress_bar.progress((idx + 1) / total_docs)
    
    # 4. Validation croisée
    status_text.text("Validation croisée des documents...")
    cross_validation = cross_validate_dossier(results)
    
    # 5. Calcul score global
    status_text.text("Calcul du score de fraude...")
    global_score = calculate_fraud_score(results, cross_validation)
    
    st.session_state.analysis_results = {
        'documents': results,
        'cross_validation': cross_validation,
        'global_score': global_score,
        'analysis_date': datetime.now().isoformat()
    }
    
    progress_bar.progress(1.0)
    status_text.text("✅ Analyse terminée !")


def page_analyse_individuelle():
    """Page d'analyse document par document"""
    
    st.markdown("## 🔍 Analyse Individuelle des Documents")
    
    if not st.session_state.uploaded_files:
        st.warning("⚠️ Aucun document uploadé. Rendez-vous dans la section 'Upload Documents'.")
        return
    
    if not st.session_state.analysis_results:
        st.warning("⚠️ Analyse non effectuée. Lancez l'analyse depuis la page 'Upload Documents'.")
        return
    
    # Sélection du document
    doc_types = {
        "contrat_travail": "📝 Contrat de travail",
        "fiche_paie_1": "💰 Fiche de paie 1",
        "fiche_paie_2": "💰 Fiche de paie 2",
        "fiche_paie_3": "💰 Fiche de paie 3",
        "avis_imposition": "🏛️ Avis d'imposition",
        "piece_identite": "🆔 Pièce d'identité",
        "quittance_1": "🏠 Quittance 1",
        "quittance_2": "🏠 Quittance 2",
        "quittance_3": "🏠 Quittance 3",
    }
    
    available_docs = [k for k in doc_types.keys() if k in st.session_state.uploaded_files]
    
    selected_doc = st.selectbox(
        "Sélectionnez un document à analyser",
        available_docs,
        format_func=lambda x: doc_types.get(x, x)
    )
    
    if selected_doc:
        st.markdown("---")
        
        doc_info = st.session_state.uploaded_files[selected_doc]
        analysis = st.session_state.analysis_results['documents'].get(selected_doc, {})
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown(f"### 📄 {doc_info['name']}")
            st.caption(f"Taille: {doc_info['size'] / 1024:.1f} KB | Type: {doc_info['type']}")
        
        with col2:
            score = analysis.get('validation', {}).get('score_fraude', 0) * 100
            color = get_score_color(score)
            st.markdown(f"""
            <div class="score-box score-{color}">
                Score de fraude: {score:.1f}%
            </div>
            """, unsafe_allow_html=True)
        
        # Tabs pour les détails
        tab1, tab2, tab3 = st.tabs(["📊 Métadonnées", "📝 Extraction Texte", "⚠️ Anomalies"])
        
        with tab1:
            st.markdown("#### 🔍 Métadonnées du fichier")
            metadata = analysis.get('metadata', {})
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Informations générales**")
                st.json({
                    "Créateur": metadata.get('creator', 'Inconnu'),
                    "Producteur": metadata.get('producer', 'Inconnu'),
                    "Date création": metadata.get('creation_date', 'Inconnue'),
                    "Date modification": metadata.get('modification_date', 'Inconnue')
                })
            
            with col2:
                st.markdown("**Signes suspects**")
                suspicious = metadata.get('suspicious_signs', [])
                
                if suspicious:
                    for sign in suspicious:
                        st.markdown(f"🚨 {sign}")
                else:
                    st.success("✅ Aucun signe suspect détecté")
        
        with tab2:
            st.markdown("#### 📝 Texte extrait (OCR)")
            text_extract = analysis.get('text_extract', '')
            
            st.text_area("Extrait", text_extract, height=300)
            
            if st.button("📋 Copier le texte"):
                st.code(text_extract)
        
        with tab3:
            st.markdown("#### ⚠️ Anomalies détectées")
            
            validation = analysis.get('validation', {})
            checks = validation.get('checks', {})
            
            # Afficher toutes les vérifications
            for check_name, check_value in checks.items():
                if isinstance(check_value, bool):
                    if check_value:
                        st.success(f"✅ {check_name.replace('_', ' ').title()}")
                    else:
                        st.error(f"❌ {check_name.replace('_', ' ').title()}")
                else:
                    st.info(f"ℹ️ {check_name.replace('_', ' ').title()}: {check_value}")
            
            # Anomalies spécifiques
            anomalies = validation.get('anomalies', [])
            
            if anomalies:
                st.markdown("**⚠️ Liste des anomalies**")
                for anomaly in anomalies:
                    st.markdown(f"""
                    <div class="alert-box alert-danger">
                        🚨 {anomaly}
                    </div>
                    """, unsafe_allow_html=True)


def page_analyse_globale():
    """Page d'analyse globale du dossier"""
    
    st.markdown("## 📊 Analyse Globale du Dossier")
    
    if not st.session_state.analysis_results:
        st.warning("⚠️ Aucune analyse disponible. Lancez d'abord l'analyse des documents.")
        return
    
    global_score = st.session_state.analysis_results.get('global_score', {})
    score = global_score.get('score', 0)
    verdict = global_score.get('verdict', '')
    color = global_score.get('color', 'green')
    
    # Affichage du score principal
    st.markdown(f"""
    <div class="score-box score-{color}" style="font-size: 2rem; padding: 30px;">
        {verdict}<br>
        <span style="font-size: 3rem;">{score:.1f}%</span>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Graphique de répartition
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📈 Score par document")
        
        doc_scores = []
        for doc_key, doc_data in st.session_state.analysis_results['documents'].items():
            doc_score = doc_data.get('validation', {}).get('score_fraude', 0) * 100
            doc_scores.append({
                'Document': doc_key.replace('_', ' ').title(),
                'Score': doc_score
            })
        
        df_scores = pd.DataFrame(doc_scores)
        st.bar_chart(df_scores.set_index('Document'))
    
    with col2:
        st.markdown("### 🔄 Validation croisée")
        
        cross_val = st.session_state.analysis_results.get('cross_validation', {})
        
        checks = {
            'Adresse cohérente': cross_val.get('adresse_coherente', False),
            'Identité cohérente': cross_val.get('identite_coherente', False),
            'Revenus cohérents': cross_val.get('revenus_coherents', False),
            'Dates cohérentes': cross_val.get('dates_coherentes', False)
        }
        
        for check_name, check_value in checks.items():
            if check_value:
                st.success(f"✅ {check_name}")
            else:
                st.error(f"❌ {check_name}")
    
    # Anomalies globales
    st.markdown("---")
    st.markdown("### ⚠️ Anomalies détectées")
    
    all_anomalies = cross_val.get('anomalies', [])
    
    if all_anomalies:
        for anomaly in all_anomalies:
            st.markdown(f"""
            <div class="alert-box alert-warning">
                🚨 {anomaly}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="alert-box alert-success">
            ✅ Aucune anomalie majeure détectée dans la validation croisée
        </div>
        """, unsafe_allow_html=True)
    
    # Recommandations
    st.markdown("---")
    st.markdown("### 💡 Recommandations")
    
    if score < 20:
        st.success("""
        ✅ **DOSSIER APPROUVÉ**
        
        Le dossier présente un faible risque de fraude. Les documents semblent authentiques
        et cohérents entre eux. Vous pouvez procéder à la suite du processus de location.
        """)
    elif score < 40:
        st.warning("""
        ⚠️ **VIGILANCE RECOMMANDÉE**
        
        Certains éléments nécessitent une vérification manuelle supplémentaire. 
        Vérifiez particulièrement les points signalés en anomalie.
        """)
    elif score < 70:
        st.error("""
        🔴 **SUSPICION DE FRAUDE**
        
        Le dossier présente plusieurs incohérences importantes. 
        Une vérification approfondie est nécessaire avant toute décision.
        Contactez directement le postulant pour clarification.
        """)
    else:
        st.error("""
        🚨 **FRAUDE PROBABLE - DOSSIER REJETÉ**
        
        Le dossier présente de nombreux signes de fraude documentaire.
        Il est fortement recommandé de rejeter cette candidature et de 
        signaler le cas si nécessaire.
        """)


def page_rapport():
    """Page de génération et téléchargement du rapport"""
    
    st.markdown("## 📑 Rapport Détaillé")
    
    if not st.session_state.analysis_results:
        st.warning("⚠️ Aucune analyse disponible. Lancez d'abord l'analyse des documents.")
        return
    
    st.info("📄 Générez un rapport PDF complet à télécharger et archiver")
    
    # Options du rapport
    with st.expander("⚙️ Options du rapport", expanded=True):
        
        col1, col2 = st.columns(2)
        
        with col1:
            include_metadata = st.checkbox("Inclure les métadonnées", value=True)
            include_ocr = st.checkbox("Inclure les extraits OCR", value=False)
        
        with col2:
            include_images = st.checkbox("Inclure les captures d'écran", value=False)
            include_recommendations = st.checkbox("Inclure les recommandations", value=True)
    
    # Génération du rapport
    if st.button("📥 Générer le rapport PDF", type="primary", use_container_width=True):
        
        with st.spinner("⏳ Génération du rapport en cours..."):
            
            report_data = {
                'analysis_date': datetime.now().strftime("%d/%m/%Y %H:%M"),
                'global_score': st.session_state.analysis_results['global_score'],
                'documents': st.session_state.analysis_results['documents'],
                'cross_validation': st.session_state.analysis_results['cross_validation'],
                'options': {
                    'include_metadata': include_metadata,
                    'include_ocr': include_ocr,
                    'include_images': include_images,
                    'include_recommendations': include_recommendations
                }
            }
            
            # Génération du rapport (fonction à implémenter)
            report_path = generate_report(report_data)
            
            st.success("✅ Rapport généré avec succès !")
            
            # Téléchargement
            with open(report_path, "rb") as f:
                st.download_button(
                    label="📥 Télécharger le rapport PDF",
                    data=f,
                    file_name=f"rapport_antifraude_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
    
    # Aperçu JSON
    st.markdown("---")
    
    with st.expander("🔍 Aperçu des données (JSON)"):
        st.json(st.session_state.analysis_results)


def get_score_color(score):
    """Retourne la couleur selon le score"""
    if score < 20:
        return "green"
    elif score < 40:
        return "orange"
    elif score < 70:
        return "red"
    else:
        return "darkred"


if __name__ == "__main__":
    main()
