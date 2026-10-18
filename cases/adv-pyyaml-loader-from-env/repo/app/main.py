import os
import yaml
from flask import Flask, request

app = Flask(__name__)
LOADER = getattr(yaml, os.environ.get("YAML_LOADER", "Full" + "Loader"))

@app.post("/import")
def do_import():
    doc = yaml.load(request.data, Loader=LOADER)
    return {"n": len(doc or {})}
