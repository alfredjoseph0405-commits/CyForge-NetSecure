# 🔐 CyForge NetSecure – Bandit Scanner Module

A Django-based security analysis tool that scans Python code for potential vulnerabilities using **Bandit** and optional **AI-based analysis**.

Built inside a Dockerized lab environment with an attacker–victim setup.

---

## 🚀 Features

* 📁 Upload Python files for scanning
* 🌐 Scan public GitHub repositories
* 🧠 AI-based vulnerability explanation (Gemini API)
* 🔍 Static analysis using Bandit
* 📂 Secure file handling using Django `MEDIA_ROOT`
* 🌍 Static frontend hosted via GitHub Pages
* 🐳 Fully containerized using Docker

---

## ⚙️ Tech Stack

* Backend: Django 5
* Security Tool: Bandit
* AI: Google Gemini (`google-genai`)
* Frontend (Static): HTML/CSS (GitHub Pages)
* Containerization: Docker + Docker Compose
* Language: Python 3.11

---

## 📁 Project Structure

```plaintext
proj/
│── core/                 # Django core settings
│── netsec/
│   ├── views.py
│   ├── forms.py
│   ├── urls.py
│   └── tools/
│       └── bandit/
│           └── bscan.py  # Main BanditTool logic
│
│── media/                     # Uploaded files stored here
│── index.html                 # Static frontend (GitHub Pages hosting)
│
│── manage.py
│── docker-compose.yaml
│── Dockerfile
```

---

## 🌐 Frontend Deployment (GitHub Pages)

The `docs/` folder contains the static frontend UI.

### To deploy:

1. Push repository to GitHub
2. Go to **Repository Settings → Pages**
3. Set:

   * Source: `main` branch
   * Folder: `/docs`

Your frontend will be live at:

```plaintext
https://<your-username>.github.io/<repo-name>/
```

---

## 🧪 How It Works

### 1. Frontend (GitHub Pages)

* Collects:

  * File upload OR GitHub repo URL
* Sends request to Django backend (API endpoint)

---

### 2. Backend (Django + Docker)

```plaintext
User Input → MEDIA_ROOT → BanditTool.execute()
```

* File stored in `/proj/media/`
* Git repo cloned (inside container)
* Bandit scan executed
* AI analysis generated

---

## 🔑 Environment Setup

Create a `.env` file in project root:

```plaintext
genai=YOUR_GEMINI_API_KEY
```

---

## 🐳 Docker Setup

### Build and run:

```bash
docker-compose build
docker-compose up
```

---

## 📂 Media Storage

All uploaded files are stored in:

```plaintext
/proj/media/
```

---

## ❗ Known Limitations

* ❌ No folder upload (intentionally removed)
* ❌ Git requires installation inside container
* ❌ Static frontend requires backend URL configuration (CORS may be needed)
* ❌ No authentication yet

---

## 🛠️ Future Improvements

* 📦 ZIP upload + extraction support
* 🔐 Authentication system
* 🌐 Full API-based frontend integration
* 📊 Better visualization of scan results

---

## 🧠 Reality Check

You now have:

* A containerized backend
* A static hosted frontend
* A security scanning pipeline

Which is dangerously close to something people would call a **“real product”**… so naturally, bugs will multiply accordingly.

---

## 👨‍💻 Author

Alfred Joseph W
Cyber Security Student

---

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

© 2026 CyForge Team
