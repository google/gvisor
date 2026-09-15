#!/usr/bin/env python3
"""
An MCP server that exposes a remote GNOME desktop as a computer-use tool.
"""

import functools
import hashlib
import io
import os
import re
import subprocess
import sys
import time
from collections import deque

import pytesseract
from mcp.server.mcpserver import Image, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from PIL import Image as PILImage
from PIL import ImageDraw

DISPLAY = os.environ.get("DISPLAY", ":1")
WIDTH = int(os.environ.get("SCREEN_WIDTH", "1280"))
HEIGHT = int(os.environ.get("SCREEN_HEIGHT", "800"))
PORT = int(os.environ.get("PORT", "8931"))

SETTLE = float(os.environ.get("ACTION_SETTLE_SECONDS", "0.6"))

# Every coordinate crossing the MCP boundary is normalized: 0-1000 across the
# width and 0-1000 down the height, independently, regardless of the real
# resolution.
#
# This is the convention Qwen-VL models emit.
NORM = 1000

# A grid ruled in those same units, so the picture and the API agree: ten
# columns and ten rows, labelled 100..900. Set SCREENSHOT_GRID=0 to turn it off.
GRID = os.environ.get("SCREENSHOT_GRID", "1") not in ("0", "false", "no")
GRID_STEP = int(os.environ.get("SCREENSHOT_GRID_STEP", "100"))

# How many identical no-op actions in a row before the tool refuses.
STUCK_LIMIT = int(os.environ.get("STUCK_LIMIT", "3"))

# Where save_screenshot writes, and what that directory is called from inside
# the OpenClaw container.
SHOT_DIR = os.environ.get("SHOT_DIR", "/shots")
# Absolute, as the OpenClaw container sees it.
SHOT_REL = os.environ.get("SHOT_REL", "/home/node/.openclaw/workspace/screenshots")
# Every screenshot is written to disk, so cap the directory rather than let a
# long session fill the workspace.
SHOT_KEEP = int(os.environ.get("SHOT_KEEP", "50"))

SHOT_MAX_BYTES = int(os.environ.get("SHOT_MAX_BYTES", "90000"))

mcp = MCPServer(
    "gnome-desktop",
    instructions=(
        "Controls a GNOME desktop with a mouse and keyboard. Every action "
        "returns the resulting screen AND a list of the text on that screen "
        "with the coordinates to click -- read that list, do not estimate "
        "positions from the image. Coordinates are normalised 0-1000 on each "
        "axis. Never guess a coordinate for something that has a label."
    ),
)

_recent: deque = deque(maxlen=STUCK_LIMIT)


def traced(fn):
    """Log every call to the container log.

    Without this the only record of a run is OpenClaw's tool names -- you can
    see that the model clicked, but not where, which is exactly the thing you
    need when it is missing its target. `docker logs` then reads as a
    transcript of what the model actually did to the screen.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        shown = ", ".join(
            [repr(a) for a in args] + [f"{k}={v!r}" for k, v in kwargs.items()]
        )
        print(f"[tool] {fn.__name__}({shown})", file=sys.stderr, flush=True)
        return fn(*args, **kwargs)

    return wrapper


def _xdo(*args: str) -> str:
    env = dict(os.environ, DISPLAY=DISPLAY)
    proc = subprocess.run(
        ["xdotool", *args], env=env, capture_output=True, text=True, timeout=30
    )
    if proc.returncode != 0:
        raise RuntimeError(f"xdotool {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _px(x: int, y: int) -> tuple[int, int]:
    """Convert a normalised (0-1000, 0-1000) point to screen pixels."""
    x, y = int(x), int(y)
    if not (0 <= x <= NORM and 0 <= y <= NORM):
        raise ValueError(
            f"({x}, {y}) is out of range: coordinates are normalised, so both x "
            f"and y must be 0-{NORM} -- x=0 is the left edge and x={NORM} the "
            f"right edge, y=0 the top and y={NORM} the bottom. Take another "
            f"screenshot and read the position off the grid."
        )
    return (
        min(WIDTH - 1, round(x * WIDTH / NORM)),
        min(HEIGHT - 1, round(y * HEIGHT / NORM)),
    )


def _norm(px: int, py: int) -> tuple[int, int]:
    """Inverse of _px: screen pixels back to normalised coordinates."""
    return round(px * NORM / WIDTH), round(py * NORM / HEIGHT)


def _raw() -> bytes:
    """Grab the screen, without the grid drawn on it."""
    path = "/tmp/screenshot.png"
    env = dict(os.environ, DISPLAY=DISPLAY)
    # -o overwrite, -p keep the pointer in the image so the model can see where
    # it left the cursor, -F path.
    subprocess.run(["scrot", "-o", "-p", "-F", path], env=env, check=True, timeout=30)
    with open(path, "rb") as fh:
        return fh.read()


def _fingerprint(png: bytes) -> str:
    """A hash that ignores noise but catches any real repaint.

    Downscaling to 64x64 greyscale first means a blinking text caret or a
    one-pixel focus ring does not read as "the screen changed", while a menu
    opening or a panel switching obviously does.
    """
    img = PILImage.open(io.BytesIO(png)).convert("L").resize((64, 64))
    return hashlib.sha256(img.tobytes()).hexdigest()


def _ocr(img: PILImage.Image) -> list[tuple[int, int, int, int, str]]:
    """One OCR pass, returning (x0, y0, x1, y1, text) boxes in pixels."""
    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    groups: dict[tuple, list] = {}
    for i, word in enumerate(data["text"]):
        # Short words ("OK", "Skip") score low; a high floor silently drops
        # exactly the buttons you most want to click.
        if not word.strip() or int(data["conf"][i]) < 25:
            continue
        key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        groups.setdefault(key, []).append(
            (word, data["left"][i], data["top"][i], data["width"][i], data["height"][i])
        )
    out = []
    for words in groups.values():
        text = " ".join(w[0] for w in words).strip()
        if not text:
            continue
        out.append(
            (
                min(w[1] for w in words),
                min(w[2] for w in words),
                max(w[1] + w[3] for w in words),
                max(w[2] + w[4] for w in words),
                text,
            )
        )
    return out


def _lines(png: bytes) -> list[tuple[int, int, str]]:
    """Every line of text on screen, as (nx, ny, text) in normalised coords.

    Tesseract expects dark text on light paper. Half of a GNOME desktop is the
    other way round -- the top bar, the overview, dialog buttons -- and those
    are exactly the controls worth clicking, so OCR the inverse too and merge.
    A line found in both passes is kept once.
    """
    img = PILImage.open(io.BytesIO(png)).convert("L")
    boxes = _ocr(img) + _ocr(PILImage.eval(img, lambda v: 255 - v))

    merged: list[tuple[int, int, int, int, str]] = []
    for box in boxes:
        x0, y0, x1, y1, text = box
        dup = any(
            t == text and abs(a - x0) < 12 and abs(b - y0) < 12
            for a, b, _, _, t in merged
        )
        if not dup:
            merged.append(box)

    out = []
    for x0, y0, x1, y1, text in merged:
        nx, ny = _norm((x0 + x1) // 2, (y0 + y1) // 2)
        out.append((nx, ny, text))
    out.sort(key=lambda t: (t[1], t[0]))
    return out


def _inventory(png: bytes, limit: int = 60) -> str:
    """The screen's text, with coordinates, attached to every result.

    find_text exists, and the model does not call it -- given a screenshot it
    guesses a coordinate instead, because guessing is always available and
    calling a tool is a decision. So do not make it a decision: every time the
    model sees the screen it also sees the list of things on the screen and
    where they are. Visual grounding stops being on the critical path for
    anything that has a label.
    """
    items = _lines(png)
    if not items:
        return "On-screen text: (none detected)"
    shown = items[:limit]
    body = "\n".join(f"({nx}, {ny})  {t}" for nx, ny, t in shown)
    more = "" if len(items) <= limit else f"\n... and {len(items) - limit} more lines"
    return (
        "On-screen text, with the normalised coordinates to click "
        f"({len(shown)} lines):\n{body}{more}"
    )


def _encodings(img: "PILImage.Image"):
    """Candidate encodings, best-looking first.

    Palette PNG before JPEG on purpose. This content is flat colour with thin
    high-contrast lines -- UI chrome, small text, and a one-pixel grid -- which
    is the worst case for JPEG ringing and the best case for quantisation: a
    palette PNG is lossless everywhere the colour count allows, so gridlines and
    glyph edges stay exact. At equal bytes it is the better picture here.
    """
    for colours in (256, 128, 64):
        yield "PNG", {"img": img.quantize(colors=colours).convert("P")}
    for quality in (85, 70, 55, 40):
        yield "JPEG", {"img": img, "quality": quality, "optimize": True}


def _for_delivery(png: bytes) -> tuple[bytes, str]:
    """Re-encode a screen grab to something cheaper to ship and store.

    Applies both to the images the tools return and to saved files. A vision
    model resamples to a fixed patch grid regardless, so bytes past the point
    where compression artefacts vanish buy nothing -- but they cost bandwidth
    on every action and disk on every save.
    """
    img = PILImage.open(io.BytesIO(png)).convert("RGB")
    for fmt, kw in _encodings(img):
        buf = io.BytesIO()
        kw.pop("img").save(buf, format=fmt, **kw)
        if buf.tell() <= SHOT_MAX_BYTES:
            return buf.getvalue(), fmt.lower()
    # Text is still legible at half size; an undisplayable image is not.
    small = img.resize((img.width // 2, img.height // 2), PILImage.LANCZOS)
    buf = io.BytesIO()
    small.save(buf, format="JPEG", quality=70, optimize=True)
    return buf.getvalue(), "jpeg"


def _save(png: bytes, name: str = "") -> str | None:
    """Write a screenshot to the shared directory; return its agent-side path.

    Returns None if the directory is not writable -- the bridge still works
    without the bind mount, it just cannot hand anything to a human.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    # Models pass "shot.png" as the name, which would otherwise produce
    # shot.png-20260915-183347.png.
    base = re.sub(r"\.(png|jpe?g|gif|webp)$", "", name, flags=re.I)
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", base).strip("-") or "screen"
    data, fmt = _for_delivery(png)
    fname = f"{safe}-{stamp}-{os.urandom(3).hex()}.{'jpg' if fmt == 'jpeg' else fmt}"
    try:
        os.makedirs(SHOT_DIR, exist_ok=True)
        with open(os.path.join(SHOT_DIR, fname), "wb") as fh:
            fh.write(data)
        shots = sorted(
            (e.path for e in os.scandir(SHOT_DIR) if e.name.endswith((".jpg", ".png"))),
            key=os.path.getmtime,
        )
        for old in shots[:-SHOT_KEEP]:
            try:
                os.unlink(old)
            except OSError:
                pass
    except OSError as exc:
        print(f"[save] {exc}", file=sys.stderr, flush=True)
        return None
    return f"{SHOT_REL}/{fname}"


# How every screen result tells the model it could be shared. Delivering an
# image is a second action the model has to decide to take, and it reliably
# forgets -- so put the path in front of it every single time rather than
# hoping it remembers a separate tool exists.
# The exact syntax the gateway parses out of a reply:
#   MEDIA_TOKEN_RE = /\bMEDIA:\s*`?([^\n]+)`?/gi
# Markdown is not an alternative. collectMarkdownImageSegments only turns
# ![x](dest) into media when dest is already a key in the attachment allowlist,
# so a markdown link to a file that was never attached is left as literal text
# and the reader sees the alt text -- the bare word "Screenshot" -- instead of
# a picture. Spell the directive out rather than describing it; "attach this as
# media" gets interpreted as markdown about half the time.
DELIVER = (
    "To show it to the user, end your reply with a line containing exactly:\n"
    "MEDIA:{path}\n"
    "Nothing else on that line. Do not use ![](...) markdown -- it renders as "
    "the alt text and delivers no image. Do not alter the path."
)


def _grid(png: bytes) -> bytes:
    """Overlay a grid labelled in normalised units on a screenshot."""
    img = PILImage.open(io.BytesIO(png)).convert("RGB")
    w, h = img.size
    draw = ImageDraw.Draw(img, "RGBA")
    # Faint enough to read UI text straight through, opaque enough to follow
    # across a white Settings panel; every other line is darker so the model
    # can count in 200s instead of counting every line.
    for n in range(GRID_STEP, NORM, GRID_STEP):
        strong = n % (GRID_STEP * 2) == 0
        alpha = 90 if strong else 45
        x = round(n * w / NORM)
        draw.line([(x, 0), (x, h)], fill=(255, 0, 255, alpha), width=1)
        draw.text((x + 3, 2), str(n), fill=(255, 0, 255, 220))
        y = round(n * h / NORM)
        draw.line([(0, y), (w, y)], fill=(255, 0, 255, alpha), width=1)
        draw.text((3, y + 3), str(n), fill=(255, 0, 255, 220))
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


def _as_image(png: bytes) -> Image:
    """The screen, gridded if configured, encoded small enough to render."""
    data, fmt = _for_delivery(_grid(png) if GRID else png)
    return Image(data=data, format=fmt)


def _acted(summary: str, before: str, signature: tuple) -> list:
    """Return the screen an action produced, and say whether it changed.

    Returning the screenshot from the action itself is the single highest-value
    thing in this file. "Screenshot after every action" is a rule the model has
    to remember and will stop obeying under pressure; making the action hand
    back its own result removes the opportunity to forget.
    """
    time.sleep(SETTLE)
    png = _raw()
    changed = _fingerprint(png) != before

    _recent.append((signature, changed))
    stuck = len(_recent) == _recent.maxlen and all(
        sig == signature and not ch for sig, ch in _recent
    )
    if stuck:
        _recent.clear()
        raise ValueError(
            f"{summary} -- and the screen has not changed for {STUCK_LIMIT} "
            f"identical calls in a row, so this is doing nothing. Stop "
            f"repeating it. Look at the last screenshot and either aim "
            f"somewhere else, use find_text to locate what you want, or "
            f"reconsider whether this is the right control."
        )

    note = (
        "screen changed"
        if changed
        else "SCREEN UNCHANGED -- that had no visible effect, so it probably "
        "missed. Do not repeat it; look at the image and try something else."
    )
    return [f"{summary}; {note}\n\n{_inventory(png)}", _as_image(png)]


@mcp.tool()
@traced
def screenshot() -> list:
    """Take a screenshot of the GNOME desktop.

    You rarely need this: every action tool already returns the screen it
    produced. Use it to look before your first action, or after waiting for
    something slow.

    The image in the result is for you to look at; it cannot itself be sent to
    anyone. The result also gives you a file path for the same screen, which is
    what you attach if someone asked to be shown it.

    A magenta grid is drawn over the image, labelled 100 to 900 along the top
    and down the left edge. Those labels are the coordinate system the click
    tools use: x runs 0-1000 from the left edge to the right edge and y runs
    0-1000 from the top edge to the bottom, whatever the image's real pixel
    size. Read a target's position off the gridlines above and to the left of
    it and interpolate; do not convert to pixels.
    """
    time.sleep(SETTLE)
    png = _raw()
    path = _save(png)
    text = _inventory(png)
    if path:
        # A bare fact, deliberately not an instruction. An imperative here gets
        # recited to the user verbatim instead of acted on -- "If you need to
        # share this image, use the message tool with..." turns up in the reply
        # as advice to the reader. Directives belong in the system prompt.
        text = f"attachable_path: {path}\n\n{text}"
    return [text, _as_image(png)]


@mcp.tool()
@traced
def save_screenshot(name: str = "") -> str:
    """Save the current screen as a PNG file and return its path.

    Use this when you have been asked to *show* someone the screen, rather than
    to look at it yourself. The screenshots the other tools return are for your
    eyes only -- they are not files and cannot be forwarded to anyone.

    This writes a real file and returns its path. Saving is only half the job:
    you must then send that path as an attachment with the `message` tool, or
    nothing reaches anyone.

    The image is saved without the coordinate grid, since it is for a person.
    """
    png = _raw()
    rel = _save(png, name)
    if not rel:
        raise RuntimeError(
            f"Could not write to {SHOT_DIR}. The bridge container needs that "
            f"directory bind-mounted from the agent's workspace."
        )
    return (
        f"Saved the screen to {rel}\n\n"
        f"YOU ARE NOT DONE. The file exists but has not been sent.\n\n"
        + DELIVER.format(path=rel)
    )


@mcp.tool()
@traced
def find_text(pattern: str) -> str:
    """Find on-screen text and return where it is.

    Give it a word or phrase, or a regular expression. It reads every line of
    text currently on screen and returns the normalised coordinates of the
    centre of each line that matches, closest-to-the-top first.

    This is how you navigate an application you do not know: rather than
    hunting across a screenshot for a sidebar entry or a button, ask where the
    label is and click the coordinates you get back. If it returns nothing, the
    text is not on this screen -- scroll or open something before guessing.
    """
    png = _raw()
    try:
        rx = re.compile(pattern, re.I)
    except re.error:
        rx = re.compile(re.escape(pattern), re.I)

    hits = [(ny, nx, t) for nx, ny, t in _lines(png) if rx.search(t)]
    if not hits:
        return (
            f"No text matching {pattern!r} is on screen right now. It may be "
            f"scrolled out of view, or behind another window, or the app that "
            f"shows it is not open yet."
        )
    hits.sort()
    return "\n".join(f"({nx}, {ny})  {text}" for ny, nx, text in hits)


@mcp.tool()
@traced
def click(x: int, y: int, button: str = "left") -> list:
    """Click at (x, y) on the desktop. button is left, middle or right.

    Coordinates are normalised: 0-1000 left to right, 0-1000 top to bottom, as
    labelled on the screenshot grid. (0, 0) is the top-left corner, (1000, 1000)
    the bottom-right, (500, 500) the middle. Returns the resulting screen.
    """
    codes = {"left": "1", "middle": "2", "right": "3"}
    if button not in codes:
        raise ValueError(f"button must be one of {sorted(codes)}")
    px, py = _px(x, y)
    before = _fingerprint(_raw())
    _xdo("mousemove", "--sync", str(px), str(py))
    _xdo("click", codes[button])
    return _acted(f"clicked {button} at ({x}, {y})", before, ("click", x, y, button))


@mcp.tool()
@traced
def double_click(x: int, y: int) -> list:
    """Double-click at (x, y), in normalised 0-1000 coordinates.

    Opens icons in Files, selects a word in a text field.
    """
    px, py = _px(x, y)
    before = _fingerprint(_raw())
    _xdo("mousemove", "--sync", str(px), str(py))
    _xdo("click", "--repeat", "2", "--delay", "80", "1")
    return _acted(f"double-clicked at ({x}, {y})", before, ("double_click", x, y))


@mcp.tool()
@traced
def move_mouse(x: int, y: int) -> list:
    """Move the pointer to normalised (x, y) without clicking, to hover."""
    px, py = _px(x, y)
    before = _fingerprint(_raw())
    _xdo("mousemove", "--sync", str(px), str(py))
    return _acted(f"moved to ({x}, {y})", before, ("move_mouse", x, y))


@mcp.tool()
@traced
def drag(from_x: int, from_y: int, to_x: int, to_y: int) -> list:
    """Drag from one normalised point to another with the left button down."""
    fx, fy = _px(from_x, from_y)
    tx, ty = _px(to_x, to_y)
    before = _fingerprint(_raw())
    _xdo("mousemove", "--sync", str(fx), str(fy))
    _xdo("mousedown", "1")
    _xdo("mousemove", "--sync", str(tx), str(ty))
    _xdo("mouseup", "1")
    return _acted(
        f"dragged ({from_x}, {from_y}) -> ({to_x}, {to_y})",
        before,
        ("drag", from_x, from_y, to_x, to_y),
    )


@mcp.tool()
@traced
def scroll(x: int, y: int, direction: str = "down", clicks: int = 3) -> list:
    """Scroll the wheel at normalised (x, y); direction up/down/left/right.

    Scroll over the thing you want to move -- a list scrolls only when the
    pointer is inside it, so aim at the panel, not at the middle of the window.
    If the result says the screen did not change, that area has nothing further
    to scroll and scrolling again will not help.
    """
    codes = {"up": "4", "down": "5", "left": "6", "right": "7"}
    if direction not in codes:
        raise ValueError(f"direction must be one of {sorted(codes)}")
    px, py = _px(x, y)
    n = max(1, min(int(clicks), 15))
    before = _fingerprint(_raw())
    _xdo("mousemove", "--sync", str(px), str(py))
    _xdo("click", "--repeat", str(n), "--delay", "60", codes[direction])
    return _acted(
        f"scrolled {direction} x{n} at ({x}, {y})",
        before,
        ("scroll", x, y, direction, n),
    )


@mcp.tool()
@traced
def type_text(text: str) -> list:
    """Type a literal string into whatever currently has focus.

    For Enter, Tab, arrows or any modifier combination use press_key instead --
    this tool types characters, it does not interpret key names.
    """
    before = _fingerprint(_raw())
    _xdo("type", "--clearmodifiers", "--delay", "25", text)
    return _acted(f"typed {text!r}", before, ("type_text", text))


@mcp.tool()
@traced
def press_key(keys: str) -> list:
    """Press a key or chord, in X keysym notation.

    Examples: "Return", "Escape", "Tab", "Down", "ctrl+l", "alt+F2",
    "ctrl+shift+t". Separate a sequence with spaces: "alt+F2 Return".

    "super" opens the GNOME Activities overview with its search box focused,
    which is how you launch an application: press_key("super"), then
    type_text("settings"), then press_key("Return"). Clicking the desktop
    itself does nothing -- there are no icons on it.
    """
    # The model types the name printed on the key; xdotool wants the X keysym.
    # Translating is cheaper than an error it has to recover from.
    alias = {
        "enter": "Return",
        "esc": "Escape",
        "del": "Delete",
        "ins": "Insert",
        "pgup": "Prior",
        "pageup": "Prior",
        "pgdn": "Next",
        "pagedown": "Next",
        "win": "super",
        "meta": "super",
        "cmd": "super",
        "space": "space",
        "up": "Up",
        "down": "Down",
        "left": "Left",
        "right": "Right",
        "backspace": "BackSpace",
        "tab": "Tab",
        "home": "Home",
        "end": "End",
    }

    def fix(chord: str) -> str:
        parts = chord.split("+")
        return "+".join(alias.get(p.lower(), p) for p in parts)

    before = _fingerprint(_raw())
    for chord in keys.split():
        _xdo("key", "--clearmodifiers", fix(chord))
        time.sleep(0.15)
    return _acted(f"pressed {keys}", before, ("press_key", keys))


@mcp.tool()
@traced
def wait(seconds: float = 2.0) -> list:
    """Do nothing for a while, then return the screen.

    Use this when something is still drawing. If the screen has not changed
    after a couple of these, waiting longer will not help -- whatever you were
    expecting is not coming.
    """
    seconds = max(0.0, min(float(seconds), 30.0))
    before = _fingerprint(_raw())
    time.sleep(seconds)
    return _acted(f"waited {seconds}s", before, ("wait", seconds))


@mcp.tool()
@traced
def cursor_position() -> str:
    """Report where the pointer is, in normalised 0-1000 coordinates."""
    shell = dict(
        line.split("=", 1)
        for line in _xdo("getmouselocation", "--shell").splitlines()
        if "=" in line
    )
    px, py = int(shell["X"]), int(shell["Y"])
    nx, ny = _norm(px, py)
    return f"pointer at ({nx}, {ny}) normalised, pixel ({px}, {py})"


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=PORT,
        # OpenClaw reaches this over the Docker bridge, so the Host header is
        # the container name and the SDK's DNS-rebinding protection -- which
        # only expects localhost -- would reject every request. Nothing outside
        # the bridge can route to this container in the first place.
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        ),
    )
