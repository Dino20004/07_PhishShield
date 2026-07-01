import os
import sys

def install_and_import(package):
    import importlib
    try:
        importlib.import_module(package)
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Make sure Pillow is installed
install_and_import('Pillow')

from PIL import Image, ImageDraw

def create_shield_icon(size, filename):
    # Create image with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Scale coordinates based on size
    pad = max(1, size // 10)
    
    # Outer circle/shield background (indigo color matching UI theme)
    draw.ellipse([pad, pad, size - pad, size - pad], fill=(99, 102, 241, 255))
    
    # Inner circle (dark background)
    inner_pad = pad + max(1, size // 12)
    draw.ellipse([inner_pad, inner_pad, size - inner_pad, size - inner_pad], fill=(11, 15, 25, 255))
    
    # Draw simple shield outline / lock icon in center
    center = size // 2
    w = max(2, size // 6)
    
    # Shield shape coordinates
    if size >= 32:
        shield_pts = [
            (center - w, center - w),
            (center + w, center - w),
            (center + w, center),
            (center, center + int(w * 1.5)),
            (center - w, center),
        ]
        draw.polygon(shield_pts, fill=(34, 197, 94, 255)) # Green shield center
    else:
        # Mini lock/shield for 16x16
        draw.rectangle([center - w, center - w, center + w, center + w], fill=(34, 197, 94, 255))

    os.makedirs(os.path.dirname(filename), exist_ok=True)
    img.save(filename, 'PNG')
    print(f"Generated icon: {filename} ({size}x{size})")

if __name__ == "__main__":
    assets_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
    create_shield_icon(16, os.path.join(assets_dir, "icon16.png"))
    create_shield_icon(32, os.path.join(assets_dir, "icon32.png"))
    create_shield_icon(48, os.path.join(assets_dir, "icon48.png"))
    create_shield_icon(128, os.path.join(assets_dir, "icon128.png"))
