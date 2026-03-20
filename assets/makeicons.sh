#!/bin/sh
# -*- coding: utf-8 -*-

srcdir="$(realpath "$0" | xargs dirname)"
srcdir="$srcdir/.."

. "$srcdir/scripts/lib.sh"

svg="$srcdir/assets/letmein-logo.svg"
outdir="$srcdir/assets"

SIZES="16 24 32 48 64 128 256 512"

command -v inkscape >/dev/null 2>&1 || die "inkscape not found. Please install inkscape."
command -v rsvg-convert >/dev/null 2>&1 || die "rsvg-convert not found. Please install librsvg."
command -v convert >/dev/null 2>&1 || die "convert not found. Please install ImageMagick."
command -v python3 >/dev/null 2>&1 || die "python3 not found. Please install python3."
python3 -c "import lxml" 2>/dev/null || die "python3-lxml not found. Please install python3-lxml."

render()
{
    size="$1"
    out="$2"
    inkscape \
        --export-type=png \
        --export-filename="$out" \
        --export-width="$size" \
        "$svg" >/dev/null 2>&1
}

for size in $SIZES; do
    out="$outdir/letmein-logo-${size}.png"
    info "Rendering ${size}x${size} -> $out"
    render "$size" "$out" || die "Failed to render ${size}x${size}"
done

for size_dir in "48:mipmap-mdpi" "72:mipmap-hdpi" "96:mipmap-xhdpi" "144:mipmap-xxhdpi" "192:mipmap-xxxhdpi"; do
    info "Rendering Android icon ${size_dir%%:*}x${size_dir%%:*} -> android/res/${size_dir##*:}/ic_launcher.webp"
    size="${size_dir%%:*}"
    dir="${size_dir##*:}"
    rsvg-convert -w "$size" -h "$size" assets/letmein-logo.svg -o /tmp/ic_launcher_${size}.png
    mkdir -p "android/res/${dir}"
    convert /tmp/ic_launcher_${size}.png -define webp:lossless=true android/res/${dir}/ic_launcher.webp
done

info "Generating android/res/drawable/ic_launcher_background.xml"
mkdir -p "$srcdir/android/res/drawable"
cat > "$srcdir/android/res/drawable/ic_launcher_background.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path
        android:fillColor="#FFFFFF"
        android:pathData="M0,0h108v108h-108z" />
</vector>
EOF

info "Generating android/res/drawable-v24/ic_launcher_foreground.xml"
mkdir -p "$srcdir/android/res/drawable-v24"
python3 "$srcdir/assets/svg2vd.py" "$svg" \
    "$srcdir/android/res/drawable-v24/ic_launcher_foreground.xml" \
    || die "Failed to generate ic_launcher_foreground.xml"

# vim: ts=4 sw=4 expandtab
