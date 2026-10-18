from flask import Flask, request
import yaml
from app.config import load_config

app = Flask(__name__)
CONFIG = load_config("config.yml")

@app.post("/validate")
def validate():
    doc = yaml.safe_load(request.data)
    return {"keys": sorted(doc or {})}
