import uvicorn
import os

if __name__ == "__main__":
    print("=" * 60)
    print("AI Password Auditor - Backend API Server Starting...")
    print("Swagger docs will be available at: http://127.0.0.1:8000/docs")
    print("=" * 60)
    
    # Run FastAPI app using uvicorn
    # app:app is inside app/main.py
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
