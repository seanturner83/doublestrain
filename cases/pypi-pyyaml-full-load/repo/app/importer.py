import yaml

def import_pipeline(stream):
    return yaml.load(stream, Loader=yaml.FullLoader)
