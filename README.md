# Krypto 💰  
**Crypto Price Tracker Web App (Local + AWS Deployment Ready)**

Krypto is a full-stack cryptocurrency price tracking application built using **Flask (Python)** and integrates with **AWS services** including **DynamoDB (Users, Alerts, AdminConfig)** and **SNS notifications**. The app allows users to view live crypto prices, save favorites, set price alerts via email, and includes an admin dashboard.

This project is structured to run:
- 🔹 Locally with `app.py`  
- ☁️ On AWS EC2 using `app_aws.py`

---

## 🚀 Features

- 🪙 Live crypto price data fetched from CoinGecko API  
- 📈 Display top coins and detailed coin pages with chart data  
- ⭐ Add and manage favorite coins  
- 📧 Email alerts via AWS SNS when prices drop below user-set thresholds  
- 👤 User signup & login  
- 👨‍💻 Admin dashboard for user overview  
- ☁️ AWS-ready backend with DynamoDB + SNS  
- 🧰 Separation of local and AWS deployment logic for flexibility

---

## 📂 Repository Structure

```
Krypto/
├── templates/ # HTML templates
├── static/ # CSS/JS assets
├── app.py # Local Flask app
├── app_aws.py # AWS-integrated Flask app
├── requirements.txt # Python dependencies
├── .gitignore
└── README.md
```


---

## 🛠 Technologies Used

| Layer | Technology |
|-------|------------|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript, Jinja2 |
| Database | AWS DynamoDB |
| Email Alerts | AWS SNS |
| Hosting | AWS EC2 |
| Data Provider | CoinGecko API |

---

## 📥 Getting Started (Local Development)

### 🧾 Clone the Repository

```bash
git clone https://github.com/aryandevtyagi10/-Krypto.git
cd -Krypto
```

##🧰 Create Virtual Environment
```
python -m venv venv
```

## 🟢 Activate Environment
Windows
```
bash
.\venv\Scripts\activate
```

macOS / Linux
```
bash
source venv/bin/activate
```

## 📦 Install Dependencies
```
bash
pip install -r requirements.txt
```

## 🚀 Run Locally
```bash
python app.py
```

## Open your browser and go to:
```
http://localhost:5000
```
