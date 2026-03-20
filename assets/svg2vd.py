#!/usr/bin/env python3
"""
Convert a simple SVG (single <g> with translate/scale transform) to an
Android Vector Drawable XML.  Only M/m, L/l, C/c and Z/z path commands are
handled - that is sufficient for the letmein logo SVG.
"""

import re
import sys
from lxml import etree

def parse_transform(t):
    """Return (tx, ty, sx, sy) from 'translate(tx,ty) scale(sx,sy)'.
    """
    tx, ty, sx, sy = 0.0, 0.0, 1.0, 1.0
    for fn, raw in re.findall(r'(\w+)\(([^)]+)\)', t):
        vals = list(map(float, re.split(r'[\s,]+', raw.strip())))
        if fn == 'translate':
            tx, ty = vals[0], vals[1] if len(vals) > 1 else 0.0
        elif fn == 'scale':
            sx = vals[0]
            sy = vals[1] if len(vals) > 1 else sx
    return tx, ty, sx, sy

def parse_path(d):
    """Yield (cmd, args) for each individual path command application.
    """
    tokens = re.findall(
        r'[MmCcLlZz]|[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?', d)
    nargs = {'M': 2, 'm': 2, 'L': 2, 'l': 2, 'C': 6, 'c': 6, 'Z': 0, 'z': 0}
    i, cmd = 0, None
    while i < len(tokens):
        t = tokens[i]
        if t in nargs:
            cmd = t
            i += 1
            if nargs[cmd] == 0:
                yield cmd, []
                cmd = None
            continue
        if cmd is None:
            i += 1
            continue
        n = nargs[cmd]
        args = [float(tokens[i + k]) for k in range(n)]
        i += n
        yield cmd, args
        # Implicit command repetition rules
        if cmd == 'M':
            cmd = 'L'
        elif cmd == 'm':
            cmd = 'l'

def fmt(v):
    s = f'{v:.4f}'.rstrip('0').rstrip('.')
    return s if s and s != '-' else '0'

def main():
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} input.svg output.xml', file=sys.stderr)
        sys.exit(1)

    svg_file, out_file = sys.argv[1], sys.argv[2]
    VIEWPORT = 108.0

    tree = etree.parse(svg_file)
    root = tree.getroot()
    NS = 'http://www.w3.org/2000/svg'

    # SVG viewport size from viewBox or width/height attributes
    vb = root.get('viewBox', '').split()
    svgw = float(vb[2]) if len(vb) >= 4 else float(root.get('width', VIEWPORT))
    svgh = float(vb[3]) if len(vb) >= 4 else float(root.get('height', VIEWPORT))

    # Find the paths group and its transform
    g = root.find(f'.//{{{NS}}}g')
    fill = g.get('fill', '#000000')
    tx, ty, sx, sy = parse_transform(g.get('transform', ''))

    # Fit the SVG uniformly into the square VD viewport (contain, centred)
    fit = VIEWPORT / max(svgw, svgh)
    xoff = (VIEWPORT - svgw * fit) / 2
    yoff = (VIEWPORT - svgh * fit) / 2

    # Absolute point: path(x,y) -> SVG(sx*x+tx, sy*y+ty) -> VD
    def fa(x, y):
        xs = sx * x + tx
        ys = sy * y + ty
        return xs * fit + xoff, ys * fit + yoff

    # Relative delta: only scale applies, not translation
    def fr(dx, dy):
        return dx * sx * fit, dy * sy * fit

    def convert_path(d):
        parts = []
        for cmd, a in parse_path(d):
            if cmd in ('Z', 'z'):
                parts.append('Z')
            elif cmd == 'M':
                x, y = fa(a[0], a[1])
                parts.append(f'M{fmt(x)},{fmt(y)}')
            elif cmd == 'm':
                dx, dy = fr(a[0], a[1])
                parts.append(f'm{fmt(dx)},{fmt(dy)}')
            elif cmd == 'L':
                x, y = fa(a[0], a[1])
                parts.append(f'L{fmt(x)},{fmt(y)}')
            elif cmd == 'l':
                dx, dy = fr(a[0], a[1])
                parts.append(f'l{fmt(dx)},{fmt(dy)}')
            elif cmd == 'c':
                pts = []
                for j in range(0, 6, 2):
                    dx, dy = fr(a[j], a[j + 1])
                    pts += [fmt(dx), fmt(dy)]
                parts.append(f'c{",".join(pts)}')
        return ' '.join(parts)

    paths = g.findall(f'{{{NS}}}path')
    vp = int(VIEWPORT)
    path_elems = '\n'.join(
        f'    <path\n'
        f'        android:fillColor="{fill}"\n'
        f'        android:pathData="{convert_path(p.get("d", ""))}" />'
        for p in paths
    )

    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
        f'    android:width="{vp}dp"\n'
        f'    android:height="{vp}dp"\n'
        f'    android:viewportWidth="{vp}"\n'
        f'    android:viewportHeight="{vp}">\n'
        f'{path_elems}\n'
        '</vector>\n'
    )

    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(xml)
    print(f'Written {out_file}')

if __name__ == '__main__':
    main()
