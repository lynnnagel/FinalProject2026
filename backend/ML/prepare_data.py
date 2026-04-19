import pandas as pd

# --- emails.csv (Kaggle phishing dataset) ---
df = pd.read_csv("ML/data/emails.csv", encoding="utf-8", on_bad_lines="skip")
# check which columns are there:
print("Columns:", df.columns.tolist())
# התאימי לפי מה שרואים, לדוגמה:
# df = df.rename(columns={"Email Text": "text", "Email Type": "label"})
# df["label"] = df["label"].map({"Phishing Email": 1, "Safe Email": 0})
# df[["text","label"]].dropna().to_csv("ML/data/emails.csv", index=False)

# --- enron_legitimate.csv ---
df_enron = pd.read_csv("ML/data/enron_legitimate.csv", encoding="utf-8", on_bad_lines="skip")
print("Enron columns:", df_enron.columns.tolist())
# לדוגמה: df_enron = df_enron.rename(columns={"message": "text"})
# df_enron["label"] = 0
# df_enron[["text","label"]].dropna().head(20000).to_csv("ML/data/enron_legitimate.csv", index=False)
