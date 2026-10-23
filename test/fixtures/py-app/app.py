# Fixture: both pinned packages are imported.
import yaml
from jinja2 import Template


def render(src, data):
    return Template(src).render(**yaml.safe_load(data))
