'''
Predict whether an authentication attempt will succeed (success = True) based on session behavior, nonce characteristics, protocol type, and whether attacks were present.
'''
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

df = pd.read_csv("C:\\Users\\mega6\\OneDrive\\Desktop\\Symmetric-Key-Challenge-Response-Insight-Generator\\data\\results\\auth_dataset.csv")

df['response_time'] = df['response_time'].fillna(df['response_time'].median())
df['nonce_entropy'] = df['nonce_entropy'].fillna(df['nonce_entropy'].median())

bool_cols = ['success', 'attack_flag', 'is_replay', 'is_random_guess']
for col in bool_cols:
    df[col] = df[col].astype(str).str.lower().map({'true': 1, 'false': 0})

df['ra_len'] = df['ra'].fillna('').apply(len)
df['rb_len'] = df['rb'].fillna('').apply(len)

def hex_similarity(a, b):
    if pd.isna(a) or pd.isna(b) or len(a) == 0 or len(b) == 0:
        return 0
    return sum(1 for x, y in zip(a, b) if x == y) / min(len(a), len(b))

df['nonce_similarity'] = df.apply(lambda x: hex_similarity(x['ra'], x['rb']), axis=1)

df = df.sort_values(by='timestamp')
df['time_diff'] = df['timestamp'].diff().fillna(0)

le = LabelEncoder()
df['protocol_type_enc'] = le.fit_transform(df['protocol_type'])

y = df['success']

features = [
    'protocol_type_enc',
    'response_time',
    'nonce_entropy',
    'ra_len',
    'rb_len',
    'nonce_similarity',
    'time_diff',
    'attack_flag',
    'is_replay',
    'is_random_guess'
]

X = df[features]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.25, random_state=42, stratify=y
)

gb = GradientBoostingClassifier(
    n_estimators=200,
    learning_rate=0.05,
    max_depth=3,
    random_state=42
)
gb.fit(X_train, y_train)

y_pred = gb.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=['Fail','Success']))

importances = pd.Series(gb.feature_importances_, index=features).sort_values(ascending=False)
print("\nFeature Importances:\n", importances)
