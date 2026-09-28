#  Phishing URL Detector

A lightweight, real-time machine learning system that classifies URLs as **phishing** or **legitimate** using 23 structural and lexical URL features. Includes an interactive Streamlit dashboard for live scanning, feature inspection, and analytics.

---

##  Overview

Phishing attacks remain one of the most common and effective cybersecurity threats, causing billions in losses annually. Traditional blacklist-based defenses fail against newly registered phishing domains.

This project builds an **ML-based detector** that classifies URLs by learning patterns in their structure — enabling **real-time, low-latency detection** suitable for browser extensions, mobile apps, or edge devices.

---

##  Features

- **23 engineered features** across lexical, structural, statistical, and security-heuristic categories
- **Random Forest classifier** trained on **40,000 balanced URLs** (20k phishing + 20k legit)
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
| **Total** | — | **40,000** | 50/50 balanced |

Train/Test split: **80% / 20%** (stratified).

---

##  Feature Engineering (23 Features)

| Category | Features |
|---|---|
| **Length** | `url_length`, `host_length`, `path_length` |
| **Character counts** | `num_dots`, `num_hyphens`, `num_underscores`, `num_digits`, `num_special` |
| **Structural** | `num_slashes`, `num_subdomains`, `has_ip`, `has_at`, `is_https` |
| **Statistical** | `entropy`, `digit_ratio`, `special_ratio` |
| **Security heuristics** | `suspicious_tld`, `shortener`, `has_port`, `brand_in_subdomain` |
| **Query/Path** | `path_depth`, `query_length`, `num_query_params` |

---

##  Model Performance

| Metric | Score |
|---|---|
| Accuracy | ~99% |
| Precision | ~99% |
| Recall | ~99% |
| F1-score | ~99% |
| ROC-AUC | ~0.999 |
| Inference time | < 2 ms / URL |

---

##  Quick Start

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
