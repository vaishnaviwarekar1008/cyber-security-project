import os
from flask import Flask, request, render_template, redirect, session
from werkzeug.utils import secure_filename
import joblib
import pefile

# -----------------------------------------
# Setup Flask App
# -----------------------------------------
app = Flask(__name__)
app.secret_key = '63fe681edf3e4de744981cde95b0fd808db792b76cd05ac563fbdb04096ade49'  

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
model = joblib.load("models/malware_model.pkl")

# -----------------------------------------
# Feature Extraction Function
# -----------------------------------------
def extract_features(file_path):
    try:
        pe = pefile.PE(file_path)
        features = [
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            pe.OPTIONAL_HEADER.ImageBase,
            pe.OPTIONAL_HEADER.CheckSum,
            pe.OPTIONAL_HEADER.DllCharacteristics,
            pe.OPTIONAL_HEADER.FileAlignment
        ]
    except Exception as e:
        print(f"❌ Feature extraction error: {e}")
        features = [0, 0, 0, 0, 0]
    return features

# -----------------------------------------
# Main Route: Handles GET + POST
# -----------------------------------------
@app.route('/', methods=['GET', 'POST'])
def index():
    prediction = session.get('prediction')  # 🧠 persistent prediction from last scan
    filename = session.get('filename')

    if request.method == 'POST':
        uploaded_file = request.files['file']

        if uploaded_file and uploaded_file.filename:
            original_filename = uploaded_file.filename
            filename = secure_filename(original_filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(file_path)

            print("🧾 Received:", original_filename)
            print("🧼 Saved as:", filename)

            try:
                # Simulated test malware (for debugging)
                if filename.strip().lower() == "fake_malware.exe":
                    print("🧨 Simulated malware triggered!")
                    result = 1
                else:
                    features = extract_features(file_path)
                    print("📊 Features:", features)
                    result = model.predict([features])[0]

                prediction = 'MALWARE' if result == 1 else 'Safe'
            except Exception as e:
                prediction = f"❌ Error: {str(e)}"

            # 💾 Store prediction in session
            session['prediction'] = prediction
            session['filename'] = filename

            return redirect('/')  # 🧼 Prevent resubmission on refresh

    return render_template('index.html', prediction=prediction, filename=filename)

# -----------------------------------------
# Start Server
# -----------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
