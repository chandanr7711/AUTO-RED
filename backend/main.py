from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.models.database import init_db
from backend.routers import scan

app = FastAPI(
    title="AutoRed - AI-Assisted Red Teaming Orchestrator",
    version="0.3.0",
    description="Orchestrates recon and vulnerability scanning tools against explicitly authorized targets only.",
)

# Allow the Streamlit dashboard (different port) to call this API from the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def home():
    return {"message": "AutoRed is running", "status": "active", "version": app.version}


app.include_router(scan.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
