import os

from PIL import Image, ImageDraw, ImageFilter

ROOT = r"C:\Users\mohsen\.openclaw-autoclaw\workspace\terminus-secrets"
WEB = os.path.join(ROOT, "server", "web")
WIN = os.path.join(ROOT, "windows-app", "electron")

BG = (7, 11, 17, 255)
TEAL = (62, 224, 197, 255)


def diamond(draw, cx, cy, radius, width, color):
    points = [(cx, cy - radius), (cx + radius, cy), (cx, cy + radius), (cx - radius, cy)]
    draw.line(points + [points[0]], fill=color, width=width, joint="curve")


def render(size: int, maskable: bool = False) -> Image.Image:
    scale = 4
    canvas = size * scale
    img = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    radius = int(canvas * 0.22)
    draw.rounded_rectangle([0, 0, canvas - 1, canvas - 1], radius=radius, fill=BG)

    # soft inner glow
    glow = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(glow)
    gdraw.ellipse(
        [-canvas * 0.2, -canvas * 0.45, canvas * 1.2, canvas * 0.75],
        fill=(28, 120, 108, 70),
    )
    glow = glow.filter(ImageFilter.GaussianBlur(canvas * 0.12))
    img.alpha_composite(glow)

    center = canvas / 2
    scale_factor = 0.68 if maskable else 0.80
    r = canvas * scale_factor * 0.5
    width = max(2, int(canvas * 0.035))

    diamond(draw, center, center, r, width, TEAL)
    key_r = r * 0.30
    draw.ellipse(
        [center - key_r, center - r * 0.30 - key_r, center + key_r, center - r * 0.30 + key_r],
        outline=TEAL,
        width=width,
    )
    draw.line(
        [center, center - r * 0.30 + key_r, center, center + r * 0.30],
        fill=TEAL,
        width=width,
    )

    return img.resize((size, size), Image.LANCZOS)


def main():
    os.makedirs(WEB, exist_ok=True)
    os.makedirs(WIN, exist_ok=True)

    render(192).save(os.path.join(WEB, "icon-192.png"))
    render(512).save(os.path.join(WEB, "icon-512.png"))
    render(512, maskable=True).save(os.path.join(WEB, "icon-maskable-512.png"))
    render(512).save(os.path.join(WEB, "icon.png"))

    icon = render(256)
    icon.save(
        os.path.join(WIN, "icon.ico"),
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    icon.save(os.path.join(WIN, "icon.png"))
    print("icons written")


if __name__ == "__main__":
    main()
