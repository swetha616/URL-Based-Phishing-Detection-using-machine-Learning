# 🛡️ Phishing URL Detector

A lightweight, real-time machine learning system that classifies URLs as **phishing** or **legitimate** using 27 structural, lexical, and typosquat-aware URL features. Includes an interactive Streamlit dashboard for live scanning, feature inspection, and analytics.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-orange)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-red)

---

##  Overview

Phishing attacks remain one of the most common and effective cybersecurity threats, causing billions in losses annually. Traditional blacklist-based defenses fail against newly registered phishing domains.

This project builds an **ML-based detector** that classifies URLs by learning patterns in their structure — enabling **real-time, low-latency detection** suitable for browser extensions, mobile apps, or edge devices.

---

## Features

- **27 engineered features** across lexical, structural, statistical, and typosquat-aware categories
- **Random Forest classifier** trained on **44,000+ balanced URLs**
- **Typosquatting detection** via Levenshtein distance + homoglyph normalization
- **Whitelist safeguard** for top-ranked domains — defense-in-depth pattern
- **Real-time scanning** — sub-2ms per-URL inference
- **Interactive Streamlit dashboard** with:
  - Live URL detection with confidence scores
  - Feature-by-feature breakdown
  - Scan history + KPI metrics
  - Probability distribution & timeline charts
  - CSV export
- **No Kaggle datasets** — built entirely from research-grade sources (PhishTank + Tranco)

---

##  Dataset

| Source | Type | Count | Role |
|---|---|---|---|
| [PhishTank](https://phishtank.org/) | Verified phishing URLs | 20,000 | Positive class (label = 1) |
| [Tranco Top-1M](https://tranco-list.eu/) | Top-ranked legitimate domains | 20,000 | Negative class (label = 0) |
| **Synthetic typosquats** | Generated adversarial samples | ~4,000 | Positive class (label = 1) |
| **Total** | — | **~44,000** | Balanced |

Train/Test split: **80% / 20%** (stratified).

**Data cleaning:** PhishTank URLs hosted on legitimate top-ranked domains (e.g., `sites.google.com`, `docs.google.com`) were removed to prevent label contamination.

---

## Feature Engineering (27 Features)

| Category | Features |
|---|---|
| **Length** | `url_length`, `host_length`, `path_length` |
| **Character counts** | `num_dots`, `num_hyphens`, `num_underscores`, `num_digits`, `num_special` |
| **Structural** | `num_slashes`, `num_subdomains`, `has_ip`, `has_at`, `is_https` |
| **Statistical** | `entropy`, `digit_ratio`, `special_ratio` |
| **Security heuristics** | `suspicious_tld`, `shortener`, `has_port`, `brand_in_subdomain` |
| **Query/Path** | `path_depth`, `query_length`, `num_query_params` |
| **Typosquat-aware** | `min_brand_dist` (Levenshtein), `homoglyph_brand_match`, `is_exact_brand`, `is_whitelisted` |

---

##  Model Performance

| Metric | Score |
|---|---|
| Accuracy (test split) | **96.7%** |
| Precision | ~97% |
| Recall | ~97% |
| F1-score | ~96% |
| ROC-AUC | ~0.99 |
| Curated 30-URL test | **30/30 = 100%** |
| Inference time | < 2 ms / URL |

### Curated Test Results

| Category | Result |
|---|---|
| Legitimate top-ranked sites | 12/12  |
| Structural phishing | 8/8  |
| Typosquatting attacks | 10/10  |

---

## Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/swetha616/phish-detector.git
cd phish-detector
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the dashboard
```bash
streamlit run app.py
```
Open http://localhost:8501 in your browser.

### Usage
Launch the app: streamlit run app.py

Paste any URL into the Detect tab

Click Scan → get an instant prediction with confidence

View analytics in the Dashboard tab after multiple scans
