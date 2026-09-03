"""Renders architecture.excalidraw to a flat SVG preview.

An approximation, not Excalidraw output: straight strokes and Helvetica rather
than the sketchy Virgil styling the app applies. It exists so the diagram is
visible on GitHub and so layout regressions are catchable without opening the
app. The .excalidraw file is the source of truth.

    python docs/preview.py docs/architecture.svg
"""

import json, html, sys
d=json.load(open("docs/architecture.excalidraw")); els=[e for e in d["elements"] if not e.get("isDeleted")]
byid={e["id"]:e for e in els}
out=['<svg xmlns="http://www.w3.org/2000/svg" width="1900" height="1260" viewBox="0 0 1900 1260"><rect width="100%" height="100%" fill="#fff"/>']
for e in els:
    if e["type"]=="rectangle":
        fill=e["backgroundColor"] if e["backgroundColor"]!="transparent" else "none"
        dash=' stroke-dasharray="8 6"' if e.get("strokeStyle")=="dashed" else ""
        out.append(f'<rect x="{e["x"]}" y="{e["y"]}" width="{e["width"]}" height="{e["height"]}" rx="8" fill="{fill}" stroke="{e["strokeColor"]}" stroke-width="2"{dash}/>')
for e in els:
    if e["type"]=="arrow":
        pts=[(e["x"]+p[0], e["y"]+p[1]) for p in e["points"]]
        out.append('<path d="M '+" L ".join(f"{x},{y}" for x,y in pts)+f'" fill="none" stroke="{e["strokeColor"]}" stroke-width="2" marker-end="url(#a)"/>')
for e in els:
    if e["type"]!="text": continue
    fs=e["fontSize"]; lines=e["text"].split("\n")
    if e.get("containerId"):
        c=byid[e["containerId"]]; cx=c["x"]+c["width"]/2
        y0=c["y"]+c["height"]/2-(len(lines)-1)*fs*1.25/2+fs*0.35; anchor="middle"
    else:
        cx=e["x"]; y0=e["y"]+fs*0.9; anchor="start"
    for i,l in enumerate(lines):
        out.append(f'<text x="{cx}" y="{y0+i*fs*1.25}" font-family="Helvetica,Arial" font-size="{fs}" fill="{e["strokeColor"]}" text-anchor="{anchor}">{html.escape(l)}</text>')
out.append('<defs><marker id="a" markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto"><path d="M0,0 L10,4 L0,8 z" fill="#1e1e1e"/></marker></defs></svg>')
open(sys.argv[1],"w").write("".join(out))
