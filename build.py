"""Bundle index.html + src/*.js into one offline file: dist/scamshield.html (works from a phone with no internet)."""
import pathlib
root = pathlib.Path(__file__).parent
html = (root / 'index.html').read_text(encoding='utf8')
for f in ['model.js', 'engine.js']:
    js = (root / 'src' / f).read_text(encoding='utf8')
    html = html.replace(f'<script src="src/{f}"></script>', '<script>\n' + js + '\n</script>')
(root / 'dist').mkdir(exist_ok=True)
(root / 'dist' / 'scamshield.html').write_text(html, encoding='utf8')
print('built dist/scamshield.html', len(html) // 1024, 'KB')
