import re
import pandas as pd
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# LOG PATTERN එක නිවැරදි කර ඇත (අවසානයට \s+\d+ එකතු කරන ලදී)
LOG_PATTERN = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD) (.*?) HTTP/.*?" (\d{3})\s+\d+'

@app.get("/")
def read_root():
    return {"message": "Cybersecurity Log Analyzer API is Running!"}

@app.post("/api/analyze")
async def analyze_log_file(file: UploadFile = File(...)):
    contents = await file.read()
    log_text = contents.decode("utf-8")
    
    parsed_logs = []
    
    for line in log_text.splitlines():
        match = re.match(LOG_PATTERN, line)
        if match:
            ip, timestamp, method, endpoint, status_code = match.groups()
            parsed_logs.append({
                "ip": ip,
                "timestamp": timestamp,
                "method": method,
                "endpoint": endpoint,
                "status_code": int(status_code)
            })
            
    if not parsed_logs:
        return {"error": "Invalid or incompatible log file format."}
        
    df = pd.DataFrame(parsed_logs)
    
    top_ips = df['ip'].value_counts().head(5).to_dict()
    status_counts = df['status_code'].value_counts().to_dict()
    
    # Brute-force detection logic
    unauthorized_df = df[df['status_code'] == 401]
    suspicious_ips = unauthorized_df['ip'].value_counts()
    raw_alerts = suspicious_ips[suspicious_ips >= 3].to_dict()
    
    # Frontend එකට ගැළපෙන පරිදි String list එකක් ලෙස Alerts සකස් කිරීම
    alert_messages = [f"Suspicious Brute-Force Activity Detected from IP: {ip} ({count} failed 401 attempts)" for ip, count in raw_alerts.items()]
    
    # Frontend එකේ keys වලට අනුව Return response එක සකස් කිරීම
    return {
        "total_requests": len(df),
        "top_ip_addresses": top_ips,
        "status_code_counts": status_counts,
        "brute_force_alerts": alert_messages
    }