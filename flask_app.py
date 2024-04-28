import pandas as pd
from sklearn.preprocessing import LabelEncoder, OrdinalEncoder
from flask import Flask, request, jsonify, render_template, redirect
import pickle  # Simulating ML model prediction

app = Flask(__name__)
classifier_model=pickle.load(open('classifier.pkl','rb'))

df = pd.read_csv("sample.csv")
df = df[df["Label"] == "Benign"]  # Uncomment this to scan a random request.
print(df.head())
df_total_transformed = df.convert_dtypes()
features = df_total_transformed[df_total_transformed.columns[:-1]]

# labels_encoder=pickle.load(open('labels_encoder.pkl','rb'))
labels_encoder = OrdinalEncoder().fit(df_total_transformed[df_total_transformed.columns[-1]].to_numpy().reshape(-1,1))
col_wrong = []

for col in features.columns:
    try:
        features[col] = LabelEncoder().fit_transform(features[col])
    except:
        col_wrong.append(col)
        pass

print(len(col_wrong))
print(col_wrong)

# Simulate ML model prediction
def check_request_malicious(headers: pd.DataFrame):
    # In a real scenario, you would pass the headers to your ML model for prediction
    # For demonstration, let's randomly decide if a request is malicious (0) or benign (1)
    # headers.drop(["Timestamp"], inplace = True)
    response= classifier_model.predict(headers[[x for x in headers.columns if x != "Timestamp"]])
    print(list(labels_encoder.categories_[0]))
    headers_encoded={idx: ele for idx, ele in enumerate(list(labels_encoder.categories_[0]))}
   
    return {"resp": headers_encoded[response[0]], "message": "Request is malicious" if response[0]!=0 else "Request is benign"}

@app.route('/')
def home():
    # Check if the request is malicious
    is_malicious = check_request_malicious(features.sample(1)) #replace request.headers with a randome row from the datadrame.
   

    print(is_malicious)
    if is_malicious["resp"] != "Benign":
        # Redirect user if the request is detected as malicious
        return redirect('/malicious')
    else:
        # Return a welcome message if the request is benign
        return jsonify({"message": "Hello, welcome to your feed"})

@app.route('/malicious')
def malicious():
    # Render a template for malicious requests
    return jsonify({"message": "Malicious request detected, redirecting to FIDO2 Gateway"})

if __name__ == '__main__':
    app.run(debug=True)

