# **RSA Encryption & Decryption**

This project shows a simple implementation of RSA using Python.
It includes key generation, encryption, and decryption using the Extended Euclidean Algorithm.

---

## **How to Execute (Step-by-Step)**

### **1. Create a project folder**

Place these files inside it:

* `rsa_extended.py`
* `app.py`
* `requirements.txt`

---

### **2. Create and activate a virtual environment (VS Code or PowerShell)**

```bash
py -m venv .venv
```

Activate it:

```bash
.\.venv\Scripts\Activate.ps1
```

---

### **3. Install dependencies**

```bash
pip install -r requirements.txt
```

---

### **4. Run the Streamlit UI**

```bash
streamlit run app.py
```

After a few seconds, it will open automatically at:

```
http://localhost:8501
```

---

## **How to Use the App**

1. In the sidebar → **Click Generate Keys**
2. Then → **Click Load Keys**
3. Type a message → **Click Encrypt**
4. Tick **Use last generated ciphertext** → **Click Decrypt**

You will see the original plaintext recovered.


