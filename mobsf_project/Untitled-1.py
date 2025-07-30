

import os
import time
import json
import requests
from flask import Flask, render_template, request, send_file, redirect, url_for
from androguard.misc import AnalyzeAPK
import hashlib
import zipfile
from apkutils import APK
import re
from pathlib import Path
import subprocess


UPLOAD_FOLDER = 'uploads'
MOBSF_URL = 'http://localhost:8000'
API_KEY = 'bd7d26bf352b594cfdcb99878d503337bfa4b7100864c6c8b9f2f4d2d3ee0704'  # Отримай його в MobSF: Settings > API Key

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

def get_json_report(file_hash):
    headers = {'Authorization': API_KEY}
    data = {'hash': file_hash}
    
    print("[+] Retrieving JSON report...")
    response = requests.post(f'{MOBSF_URL}/api/v1/report_json', headers=headers, data=data)
    
    if response.status_code == 200:
        json_report = response.json()
        print("[+] JSON Report отримано:")
        
        # Зберігаємо у файл
        json_path = os.path.join('uploads', f"{file_hash}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, ensure_ascii=False, indent=4)

        return json_report
    else:
        raise Exception(f"JSON report failed: {response.status_code} {response.text}")

'''
не працює
def extract_manifest(apk_path, file_hash):
    try:
        from androguard.misc import AnalyzeAPK

        a, d, dx = AnalyzeAPK(apk_path)  # a — обʼєкт APK

        manifest_xml = a.get_android_manifest_xml().toprettyxml()

        manifest_path = os.path.join('uploads', f"{file_hash}_AndroidManifest.xml")
        with open(manifest_path, 'w', encoding='utf-8') as f:
            f.write(manifest_xml)

        print("[+] AndroidManifest.xml збережено:", manifest_path)
        return manifest_path
    except Exception as e:
        raise Exception(f"Помилка при витягуванні AndroidManifest.xml: {str(e)}")
'''

def calculate_md5(filepath):
    md5_hash = hashlib.md5()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

def check_test1_storage_permissions(manifest_path: str) -> None:
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if re.search(r'android\.permission\.READ_EXTERNAL_STORAGE', content):
            print("[!] READ_EXTERNAL_STORAGE вказано — ❌ небажаний дозвіл")
        else:
            print("[✓] READ_EXTERNAL_STORAGE — відсутній ✅")

        if re.search(r'android\.permission\.WRITE_EXTERNAL_STORAGE', content):
            print("[!] WRITE_EXTERNAL_STORAGE вказано — ❌ небажаний дозвіл")
        else:
            print("[✓] WRITE_EXTERNAL_STORAGE — відсутній ✅")

    except FileNotFoundError:
        print(f"[!] Файл {manifest_path} не знайдено.")

    except Exception as e:
        print(f"[!] Помилка при перевірці: {e}")

def check_test6_min_sdk_version_text(manifest_path: str, min_required: int = 11):
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            content = f.read()

        import re
        match = re.search(r'minSdkVersion\s*=\s*"[0-9]+"', content)
        if match:
            value = int(re.search(r'\d+', match.group()).group())
            if value < min_required:
                return f"[✗] minSdkVersion = {value}, менше за {min_required}"
            else:
                return f"[✓] minSdkVersion = {value}, відповідає вимогам"
        else:
            return "[!] Не знайдено minSdkVersion"
    except Exception as e:
        return f"[!] Помилка: {e}"

def check_test9_allow_backup(manifest_path: str) -> None:
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            content = f.read()

        match = re.search(r'android:allowBackup\s*=\s*"(true|false)"', content)

        if match:
            value = match.group(1).lower()
            if value == "true":
                print("[❌] allowBackup увімкнено (true) — це ПОГАНО. Дані можуть бути резервовані в хмару. Виконайте MASTG-TEST-0001")
            else:
                print("[✅] allowBackup вимкнено (false) — це ДОБРЕ. Резервне копіювання обмежено.")
        else:
            print("[⚠️] Атрибут allowBackup не знайдено в файлі. За замовчуванням він УВІМКНЕНИЙ з Android 6.0+")

    except FileNotFoundError:
        print(f"[!] Файл {manifest_path} не знайдено.")
    except Exception as e:
        print(f"[!] Помилка при перевірці: {e}")

def check_test262_is_sensitive_data_backed_up(manifest_path, backup_rules_path=None, data_extraction_rules_path=None):
    manifest_text = Path(manifest_path).read_text(encoding='utf-8')
    
    allow_backup = 'android:allowBackup="true"' in manifest_text or 'android:allowBackup' not in manifest_text
    uses_backup_rules = 'android:fullBackupContent="@xml/backup_rules"' in manifest_text
    uses_data_extraction = 'android:dataExtractionRules="@xml/data_extraction_rules"' in manifest_text

    excludes_defined = False

    if data_extraction_rules_path and Path(data_extraction_rules_path).exists():
        rules = Path(data_extraction_rules_path).read_text(encoding='utf-8')
        excludes_defined = '<exclude' in rules
    elif backup_rules_path and Path(backup_rules_path).exists():
        rules = Path(backup_rules_path).read_text(encoding='utf-8')
        excludes_defined = '<exclude' in rules

    # LOGIC:
    # Bad = True if backup is allowed and rules not declared or do not exclude anything
    if allow_backup:
        if not (uses_backup_rules or uses_data_extraction):
            return True  # bad: allows backup, but no rules declared
        if not excludes_defined:
            return True  # bad: rules declared, but nothing is excluded

    return False  # good

'''
не працює
def extract_manifest_with_jadx(apk_path, out_dir):
    try:
        os.makedirs(out_dir, exist_ok=True)
        subprocess.run(["jadx", "--no-src", "-d", out_dir, apk_path], check=True)
        manifest_path = os.path.join(out_dir, "resources", "AndroidManifest.xml")
        if os.path.exists(manifest_path):
            print(f"[+] Manifest збережено: {manifest_path}")
            return manifest_path
        else:
            print("[-] Manifest не знайдено.")
            return None
    except subprocess.CalledProcessError as e:
        print(f"[!] Помилка при запуску jadx: {e}")
        return None
''' 

ALLOWED_EXTENSIONS = ('.apk', '.ipa')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['apkfile']
        if file and file.filename.endswith(ALLOWED_EXTENSIONS):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)

            try:

                '''
                не працюючий варіант
                apk_path = filepath
                output_dir = os.path.join('uploads', os.path.splitext(file.filename)[0])
                manifest_path = extract_manifest_with_jadx(apk_path, output_dir)

                if not manifest_path:
                    return "<h3>Не вдалося витягти AndroidManifest.xml</h3>"
                '''
                    

                file_hash = upload_to_mobsf(filepath)

                # Витягнути AndroidManifest.xml
                '''
                не працюючий варіант
                print("Хеш буде рахуватися")
                file_hash = calculate_md5(filepath)
                print("Хеш пораховано")
                extract_android_manifest(filepath, file_hash)
                print("Хеш пораховано")         
                '''

                #print("HASH:")
                #print(file_hash)
                scan_file(file_hash)

                # Можна додати затримку, щоб дочекатись завершення сканування
                #time.sleep(30)

                json_report = get_json_report(file_hash)
                #print(json.dumps(json_report, indent=4, ensure_ascii=False))  # Повний JSON, красиво

                pdf_report_path = get_pdf_report(file_hash)

                return send_file(pdf_report_path, as_attachment=True)
                
                #return f"<h3>Файл {file.filename} завантажено успішно, але аналіз вимкнено.</h3>"


            except Exception as e:
                return f"<h3>Помилка: {str(e)}</h3>"

        return "<h3>Файл повинен бути .apk</h3>"

    return render_template('index.html')


if __name__ == '__main__':

    print('MASTG-TEST-0001')
    check_test1_storage_permissions('uploads/manifest.xml')
    print('MASTG-TEST-0006')
    print(check_test6_min_sdk_version_text("uploads/manifest.xml"))
    print('MASTG-TEST-0009')
    check_test9_allow_backup("uploads/manifest.xml")
    print('MASTG-TEST-0262')
    check_test9_allow_backup("uploads/manifest.xml")
    result = check_test262_is_sensitive_data_backed_up(manifest_path="uploads/manifest.xml")
    if result:
        print("⚠️ Погано: додаток може резервувати чутливі дані.")
    else:
        print("✅ Добре: чутливі дані не резервуються.")

    #app.run(debug=True)
