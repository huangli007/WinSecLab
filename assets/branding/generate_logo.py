"""
WinSecLab Logo 生成器。

设计意图：
  - 盾牌 = 安全（这个平台的领域是安全测试）
  - 盾牌内嵌放大镜 + 准星 = 检测 / 审视（"把程序放到显微镜下看"）
  - 盾牌右下一个小小的琥珀色警示点 = 发现的问题/漏洞

配色取自 App 主题：indigo 渐变底 + 白色盾牌图形 + amber 警示点。

技术：全部用 Pillow 在超采样画布（4x）上绘制，再 LANCZOS 缩到目标尺寸，
      保证边缘平滑（Windows 会按尺寸切换图标，锯齿在小尺寸上很显眼）。

产出：
  assets/branding/logo-<size>.png    各尺寸 PNG
  src/WinSecLab.App/Assets/wsl.ico   多尺寸 ICO（16/24/32/48/64/128/256）
"""
import math
import os
from PIL import Image, ImageDraw

# ── 配色（与 Theme.xaml 对齐）──
INDIGO_LT = (99, 102, 241)       # #6366F1 亮部（渐变顶）
INDIGO_DK = (55, 48, 163)        # #3730A3 暗部（渐变底）
INDIGO    = (79, 70, 229)        # #4F46E5 主色（盾牌内芯）
WHITE     = (255, 255, 255)
AMBER     = (251, 191, 36)       # #FBBF24 警示点

SS = 4  # 超采样倍率


def shield_polygon(cx, top, bottom, half_w, shoulder=0.60, corner=0.12):
    """
    干净对称的盾牌多边形。

    形状：顶边平（两角微圆）→ 两侧竖直向下 → 到 shoulder 比例处向内收 →
          底部收成一个尖角。用平滑曲线收底，避免折线感。
    """
    left = cx - half_w
    right = cx + half_w
    h = bottom - top

    pts = []
    # 顶部：从左上圆角起
    pts.append((left, top + h * corner))
    pts.append((left + half_w * corner * 0.9, top))
    pts.append((right - half_w * corner * 0.9, top))
    pts.append((right, top + h * corner))

    # 右侧直线到 shoulder
    y_sh = top + h * shoulder
    pts.append((right, y_sh))

    # 右侧向底部中心收（二次贝塞尔近似：用密集点走一条凸曲线）
    n = 28
    for i in range(n + 1):
        t = i / n
        # x: right -> cx
        x = right + (cx - right) * (1 - (1 - t) ** 2)
        # y: y_sh -> bottom，用 sin 让收口更自然
        y = y_sh + (bottom - y_sh) * math.sin(t * math.pi / 2)
        pts.append((x, y))

    # 左侧对称回来
    for i in range(n + 1):
        t = i / n
        x = cx + (left - cx) * (1 - (1 - t) ** 2)
        y = bottom + (y_sh - bottom) * math.sin(t * math.pi / 2)
        pts.append((x, y))

    pts.append((left, y_sh))
    return pts


def draw_logo(size_px):
    S = size_px * SS
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # ── 圆角方底：indigo 竖直渐变 ──
    grad = Image.new("RGBA", (S, S))
    gd = ImageDraw.Draw(grad)
    for y in range(S):
        t = y / max(1, S - 1)
        r = int(INDIGO_LT[0] + (INDIGO_DK[0] - INDIGO_LT[0]) * t)
        g = int(INDIGO_LT[1] + (INDIGO_DK[1] - INDIGO_LT[1]) * t)
        b = int(INDIGO_LT[2] + (INDIGO_DK[2] - INDIGO_LT[2]) * t)
        gd.line([(0, y), (S, y)], fill=(r, g, b, 255))

    pad = S * 0.05
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [pad, pad, S - pad, S - pad], radius=int(S * 0.225), fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)

    cx = S / 2

    # ── 盾牌：白色外轮廓 + indigo 内芯（形成一圈白边）──
    sh_half = S * 0.235
    sh_top = S * 0.205
    sh_bot = S * 0.795
    outer = shield_polygon(cx, sh_top, sh_bot, sh_half)
    d.polygon(outer, fill=WHITE)

    # 内芯：整体内缩，留出白边
    inset = S * 0.045
    inner = shield_polygon(cx, sh_top + inset * 1.05, sh_bot - inset * 1.5,
                           sh_half - inset)
    d.polygon(inner, fill=INDIGO)

    # ── 放大镜（白色），居中偏上 ──
    lens_cx = cx - S * 0.005
    lens_cy = S * 0.455
    lens_r = S * 0.085
    lw = max(2, int(S * 0.030))
    d.ellipse([lens_cx - lens_r, lens_cy - lens_r,
               lens_cx + lens_r, lens_cy + lens_r],
              outline=WHITE, width=lw)

    # 镜柄：从镜圈右下 45° 伸出，长度较短，避免戳出盾牌
    ang = math.radians(45)
    hx0 = lens_cx + lens_r * math.cos(ang)
    hy0 = lens_cy + lens_r * math.sin(ang)
    hx1 = lens_cx + (lens_r + S * 0.058) * math.cos(ang)
    hy1 = lens_cy + (lens_r + S * 0.058) * math.sin(ang)
    d.line([(hx0, hy0), (hx1, hy1)], fill=WHITE, width=int(lw * 1.15))

    # 准星十字（镜内"检测"语义）
    tick = lens_r * 0.46
    tw = max(2, int(lw * 0.62))
    d.line([(lens_cx - tick, lens_cy), (lens_cx + tick, lens_cy)], fill=WHITE, width=tw)
    d.line([(lens_cx, lens_cy - tick), (lens_cx, lens_cy + tick)], fill=WHITE, width=tw)

    # ── 琥珀警示点：位于盾牌右下内芯区域，带白描边 ──
    dot_r = S * 0.030
    dot_cx = cx + S * 0.098
    dot_cy = S * 0.640
    d.ellipse([dot_cx - dot_r, dot_cy - dot_r, dot_cx + dot_r, dot_cy + dot_r],
              fill=AMBER, outline=WHITE, width=max(1, int(S * 0.011)))

    return img.resize((size_px, size_px), Image.LANCZOS)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", ".."))
    branding = os.path.join(root, "assets", "branding")
    os.makedirs(branding, exist_ok=True)

    sizes = [512, 256, 128, 64, 48, 32, 16]
    imgs = {}
    for s in sizes:
        im = draw_logo(s)
        imgs[s] = im
        im.save(os.path.join(branding, f"logo-{s}.png"))
        print(f"  logo-{s}.png")

    ico_dir = os.path.join(root, "src", "WinSecLab.App", "Assets")
    os.makedirs(ico_dir, exist_ok=True)
    ico_path = os.path.join(ico_dir, "wsl.ico")
    imgs[256].save(ico_path, format="ICO",
                   sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"  {ico_path}")

    imgs[512].save(os.path.join(branding, "logo.png"))


if __name__ == "__main__":
    main()
