from flask import Flask, request
from app.importer import import_pipeline

app = Flask(__name__)

@app.post("/pipelines")
def upload():
    spec = import_pipeline(request.files["spec"].stream)
    return {"stages": len(spec.get("stages", []))}
