'''
Classify each authentication session into one of three classes:
1. No attack
2. Replay attack
3. Random guess attack
'''
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

df = pd.read_csv("C:\\Users\\mega6\\OneDrive\\Desktop\\Symmetric-Key-Challenge-Response-Insight-Generator\\data\\results\\auth_dataset.csv")

df['response_time'] = df['response_time'].fillna(df['response_time'].median())
df['nonce_entropy'] = df['nonce_entropy'].fillna(df['nonce_entropy'].median())

bool_cols = ['success', 'attack_flag', 'is_replay', 'is_random_guess']
for col in bool_cols:
    df[col] = df[col].astype(str).str.lower().map({'true': 1, 'false': 0})

def label_attack_type(row):
    if row['attack_flag'] == 0:
        return 0  # no attack
    elif row['is_replay'] == 1:
        return 1  # replay attack
    elif row['is_random_guess'] == 1:
        return 2  # random guess attack
    else:
        return 0  # fallback to no attack if ambiguous

df['attack_type'] = df.apply(label_attack_type, axis=1)


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

features = [
    'protocol_type_enc',
    'response_time',
    'nonce_entropy',
    'ra_len',
    'rb_len',
    'nonce_similarity',
    'time_diff',
    'success'
]

X = df[features]
y = df['attack_type']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

rf = RandomForestClassifier(
    n_estimators=300, random_state=42, class_weight='balanced_subsample'
)
rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=['no_attack','replay','random_guess']))

importances = pd.Series(rf.feature_importances_, index=features).sort_values(ascending=False)
print("\nFeature Importances:\n", importances)
