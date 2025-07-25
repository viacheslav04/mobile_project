

import os
import time
import json
import requests
from flask import Flask, render_template, request, send_file, redirect, url_for

UPLOAD_FOLDER = 'uploads'
MOBSF_URL = 'http://localhost:8000'
API_KEY = 'API_KEY'  # Отримай його в MobSF: Settings > API Key

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

    
def upload_to_mobsf(file_path):
    headers = {'Authorization': API_KEY}
    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f, 'application/vnd.android.package-archive')}
        print("[+] Uploading file to MobSF...")
        r = requests.post(f'{MOBSF_URL}/api/v1/upload', files=files, headers=headers)
    if r.status_code == 200:
        print(r.json())
        return r.json()['hash']
    else:
        print(r.status_code, r.text)
        raise Exception(f"Upload failed: {r.text}")



def scan_file(scan_hash):
    headers = {'Authorization': API_KEY, 'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'hash': scan_hash
    }

    #print("[DEBUG] JSON для скану:", data)

    response = requests.post(f'{MOBSF_URL}/api/v1/scan', data=data, headers=headers)

    #print("[DEBUG] Статус:", response.status_code)
    #print("[DEBUG] Відповідь:", response.text)  

    if response.status_code == 200:
        print("[+] Scan started")
        return response.json()
    else:
        print("[+] Scan failed")
        raise Exception(f"Scan failed: {response.text}")


def get_pdf_report(file_hash):
    headers = {'Authorization': API_KEY}
    print("[+] Retrieving PDF report...")
    r = requests.post(f'{MOBSF_URL}/api/v1/download_pdf', data={"hash": file_hash}, headers=headers)
    if r.status_code == 200:
        pdf_path = os.path.join('uploads', f"{file_hash}.pdf")
        with open(pdf_path, 'wb') as f:
            f.write(r.content)
        return pdf_path
    else:
        raise Exception(f"PDF report failed: {r.text}")

ALLOWED_EXTENSIONS = ('.apk', '.ipa')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['apkfile']
        if file and file.filename.endswith(ALLOWED_EXTENSIONS):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)

            try:
                file_hash = upload_to_mobsf(filepath)
                #print("HASH:")
                #print(file_hash)
                scan_file(file_hash)

                # Можна додати затримку, щоб дочекатись завершення сканування
                #time.sleep(30)

                pdf_report_path = get_pdf_report(file_hash)
                return send_file(pdf_report_path, as_attachment=True)

            except Exception as e:
                return f"<h3>Помилка: {str(e)}</h3>"

        return "<h3>Файл повинен бути .apk</h3>"

    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
