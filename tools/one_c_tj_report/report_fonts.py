"""Explicit font registration, called only when rendering."""
from pathlib import Path

try:
    from .report_schema import require, digest
except ImportError:
    from report_schema import require, digest


def register_fonts(config):
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    settings = config.settings['fonts']
    if 'profile' in settings:
        base = Path(__file__).parent/'assets/fonts'
        paths = (base/'LiberationSans-Regular.ttf',base/'LiberationSans-Bold.ttf')
    else:
        paths = (Path(settings['regular']),Path(settings['bold']))
    names = []
    for path in paths:
        require(path.is_file(), f'Missing font: {path}')
        name = 'Report-' + digest(path.read_bytes())[:16]
        if name not in pdfmetrics.getRegisteredFontNames():
            font = TTFont(name,str(path))
            require(all(ord(c) in font.face.charToGlyph for c in 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя'), f'Font lacks Cyrillic: {path}')
            pdfmetrics.registerFont(font)
        names.append(name)
    pdfmetrics.registerFontFamily(names[0],normal=names[0],bold=names[1])
    return tuple(names)
