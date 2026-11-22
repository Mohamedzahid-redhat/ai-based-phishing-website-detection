
# AI-Based Phishing Website Detection Using Machine Learning

An AI-powered phishing website detection project that analyzes URL and website characteristics to classify potentially malicious and legitimate websites.

## Project Overview

Phishing websites imitate legitimate websites to steal sensitive information such as login credentials and personal data.

This project uses a **Random Forest Classifier** trained on the UCI Phishing Websites Dataset to identify potentially phishing websites. It also includes a reusable feature-extraction module for analyzing live website URLs.

## Key Features

- Machine learning-based phishing website classification
- Random Forest classification model
- 25 selected input features
- 20 reusable feature-extraction functions
- Live URL feature extraction
- SSL certificate and domain information checks
- DNS and web traffic-related feature extraction
- Model and feature-order validation
- Google Colab-compatible setup

## Technologies Used

- Python
- Google Colab
- Pandas and NumPy
- Scikit-learn
- Random Forest Classifier
- Requests
- BeautifulSoup
- python-whois
- tldextract
- dnspython
- Joblib

## Dataset

**Dataset:** UCI Phishing Websites Dataset

- Total records: 11,055
- Original features: 30
- Selected model features: 25
- Target column: Result

The model was trained using 8,844 records and evaluated using 2,211 held-out records.

## Machine Learning Model

**Algorithm:** Random Forest Classifier

**Number of decision trees:** 200

**Input features:** 25

The model uses the following classification labels:

- `-1`: Phishing
- `1`: Legitimate

## Model Evaluation

| Metric | Score |
|---|---:|
| Accuracy | 96.7% |
| Precision | 96.7% |
| Recall | 96.7% |
| F1 Score | 96.7% |

These results are from the held-out dataset test split. They should not be interpreted as verified real-world detection accuracy.

## Live URL Feature Extraction

The project includes a reusable Python module named `phishing_features.py`.

It contains:
- 20 feature-extraction functions
- 25 model input features
- 18 additional feature extractors
- A unified function to collect live URL features

The feature extraction process gathers available information from a URL and its website. Some features may be unavailable depending on website restrictions, network access, or external service responses.

## Project Structure

```text
ai-based-phishing-website-detection/
│
├── Phishing_Detection_Project_py (4).ipynb
├── phishing_features.py
├── phishing_model_25.pkl
├── requirements.txt
└── README.md
```

## How to Run

1. Clone or download this repository.
2. Open the notebook in Google Colab.
3. Upload the project files to your Google Drive folder named `Phishing_Detection_Project`.
4. Ensure the model, feature module, and requirements file are in that folder.
5. Run the startup cell to install dependencies and load the model.
6. Execute the notebook cells to test the feature extraction and prediction workflow.

The startup cell currently uses a Google Drive project folder. If you use a different folder location, update `PROJECT_DIR` in the notebook.

## Disclaimer

This project is intended for educational and portfolio demonstration purposes. Predictions are machine learning estimates and are not guarantees that a website is safe or malicious. Always verify suspicious websites independently and never enter sensitive information based solely on this tool's prediction.
