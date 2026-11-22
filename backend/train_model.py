import os
import sys

# Add backend directory to path to enable package relative imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.ml_predictor import train_synthetic_model, HAS_ML_LIBS

if __name__ == "__main__":
    print("=" * 60)
    print("AI Password Auditor - Machine Learning Training Suite")
    print("=" * 60)
    
    if not HAS_ML_LIBS:
        print("[ERROR] Scikit-Learn or joblib is not installed.")
        print("Please install required packages using: pip install scikit-learn pandas numpy")
        sys.exit(1)
        
    success = train_synthetic_model()
    
    if success:
        print("\n[SUCCESS] Model training complete. Ready to run the FastAPI backend!")
    else:
        print("\n[ERROR] Model training failed.")
