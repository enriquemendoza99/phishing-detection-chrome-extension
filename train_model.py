"""
Trains the phishing-detection RandomForest classifier once and saves it
to disk with joblib
"""
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from feature_extraction import extract_url_features

df = pd.read_csv('URL dataset.csv')

# Mapping labels to binary
df['type'] = df['type'].map({'phishing': 1, 'legitimate': 0})
df = df.dropna(subset=['type'])

print("Label counts:\n", df['type'].value_counts())

# Feature extraction
feature_dicts = df['url'].apply(extract_url_features)
X = pd.DataFrame(feature_dicts.tolist())
y = df['type']

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train Classifier
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Evaluate
y_probs = clf.predict_proba(X_test)[:, 1]
threshold = 0.3
y_pred_custom = (y_probs >= threshold).astype(int)

print(f"\nEvaluation with Threshold = {threshold}")
print(confusion_matrix(y_test, y_pred_custom))
print(classification_report(y_test, y_pred_custom))

# Save the trained model to disk so app.py can load it instantly
joblib.dump(clf, 'phishing_model.pkl')
print("\nModel saved to phishing_model.pkl")