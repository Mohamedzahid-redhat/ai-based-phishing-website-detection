
# AI-Based Phishing Website Detection Using Machine Learning

## Project Overview
This project uses Machine Learning to identify potentially
phishing websites by analysing URL and website characteristics.

## Technologies Used
- Python
- Google Colab
- Pandas
- Scikit-learn
- Random Forest Classifier
- BeautifulSoup
- Requests
- RDAP and DNS
- Tranco
- Gradio

## Dataset
UCI Phishing Websites Dataset

Original dataset:
- 11,055 website records
- 30 original features

A separate model was trained using 25 selected features
for the live URL extraction demonstration.

## Machine Learning Model
Algorithm: Random Forest Classifier

Number of decision trees: 200

Training records: 8,844
Testing records: 2,211

## Model Evaluation

Accuracy: 96.7%
Precision: 96.7%
Recall: 96.7%
F1 Score: 96.7%

These results are from the held-out UCI test dataset.
They do not represent verified real-world URL accuracy.

## Application
The application uses Gradio to accept a website URL,
extract available website features and display a
preliminary phishing or legitimate classification.

## How to Run
1. Open the notebook in Google Colab.
2. Install the required Python libraries.
3. Upload phishing_model_25.pkl when requested.
4. Execute the notebook cells.
5. Launch the Gradio application.

## Disclaimer
This project is an academic demonstration.
Predictions are not guarantees that a website is
safe or malicious. Live feature extraction uses
simplified approximations.
