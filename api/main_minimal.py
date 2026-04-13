from fastapi import FastAPI

app = FastAPI(title="LinkShield API")

@app.get("/")
def root():
    return {"service": "LinkShield API", "status": "ok"}

@app.get("/health")
def health():
    return {"status": "ok"}
