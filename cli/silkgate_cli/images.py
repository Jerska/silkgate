"""Generated images: the base plus one layer per profile, tagged by a hash of what shapes them."""
import hashlib
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import console, mitm, paths


BASE_IMAGE = "debian:bookworm-slim"   # profiles layer on top of this
IMAGE_NS = "silkgate"                # generated images: silkgate/<slug>:<hash12>


# --- generated images --------------------------------------------------------
# There is no Dockerfile in this repo: an image is the base plus one layer per profile,
# synthesized here. The tag carries a hash of everything that shapes the result, so a
# session can ask for an image by profile list and get a cache hit or an honest rebuild.

_DOCKER_PLATFORMS = {"arm64": "linux/arm64", "aarch64": "linux/arm64",
                     "x86_64": "linux/amd64", "amd64": "linux/amd64"}

# What silkgate needs of any guest: its CA in the trust store and in the env vars runtimes
# read, a shell plus mkfifo/mktemp for the output relay, and /workspace.
#
# NODE_EXTRA_CA_CERTS adds to the defaults, so it names our CA alone. The others replace
# the root store (OpenSSL, rustls, Go), so they name the regenerated system bundle: Debian's
# roots and ours. The bare CA would break every later layer's setup.sh, which downloads
# from the real internet, outside the proxy.
_BASE_LAYER = """FROM {base}
RUN apt-get update \\
    && apt-get install -y --no-install-recommends ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
COPY egress-ca.pem /usr/local/share/ca-certificates/egress.crt
RUN update-ca-certificates
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/egress.crt \\
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \\
    GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt \\
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \\
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \\
    PATH=/root/.local/bin:$PATH
WORKDIR /workspace
"""


def _image_profiles(profiles):
    """The unique (name, version) instances, in order: an arg never shapes the image,
    so several instances of one profile contribute one layer set — two sessions whose
    specs differ only in args reuse one image."""
    unique = {}
    for p in profiles:
        unique.setdefault((p.name, p.version), p)
    return list(unique.values())


def image_ref(profiles, base=BASE_IMAGE):
    """`silkgate/<slug>:<hash12>` — slug to read, hash to be exact.

    The hash covers the base, _BASE_LAYER, and per profile, in order: its name, version,
    packages, and the bytes of setup.sh, rules.txt (as templates, so args don't count),
    and env. Any edit or reorder makes a new image, so a cache hit is never stale.
    """
    profiles = _image_profiles(profiles)
    h = hashlib.sha256(base.encode())
    h.update(b"\0" + _BASE_LAYER.encode())
    for p in profiles:
        h.update(b"\0" + p.image_spec.encode())
        h.update(b"\0" + " ".join(p.packages).encode())
        for text in (p.setup, p.rules, p.env):
            h.update(b"\0" + text.encode())
    slug = "-".join(dict.fromkeys(p.name for p in profiles)) or "base"
    return f"{IMAGE_NS}/{slug[:60]}:{h.hexdigest()[:12]}"


def image_in_msb(ref):
    msb = shutil.which("msb")
    if not msb:
        return False
    out = subprocess.run([msb, "image", "ls"], capture_output=True, text=True).stdout
    return any(line.split()[:1] == [ref] for line in out.splitlines()[1:])


def write_build_context(directory, profiles, base):
    """The synthesized Dockerfile plus everything it COPYs."""
    profiles = _image_profiles(profiles)        # one layer set per profile, args aside
    shutil.copyfile(mitm.ensure_ca(), directory / "egress-ca.pem")
    lines = [_BASE_LAYER.format(base=base)]
    # Every profile's `packages` in one transaction: apt resolves them together, shared
    # dependencies land once, and no setup.sh has to carry update/clean boilerplate. A
    # profile that needs a package from outside the distro's repos adds the source and
    # installs it in its own setup.sh instead.
    packages = sorted({pkg for p in profiles for pkg in p.packages})
    if packages:
        lines.append("RUN apt-get update \\\n"
                     "    && apt-get install -y --no-install-recommends \\\n        "
                     + " \\\n        ".join(packages)
                     + " \\\n    && rm -rf /var/lib/apt/lists/*")
    for p in profiles:
        if p.setup.strip():
            (directory / f"setup-{p.name}.sh").write_text(p.setup)
            # One COPY+RUN per profile, so editing the last one rebuilds only its layer.
            lines.append(f"COPY setup-{p.name}.sh /silkgate/setup-{p.name}.sh")
            lines.append(f'RUN VERSION="{p.version or ""}" sh /silkgate/setup-{p.name}.sh')
        if p.env_pairs():
            lines.append("ENV " + " \\\n    ".join(p.env_pairs()))
    (directory / "Dockerfile").write_text("\n".join(lines) + "\n")


def docker_env():
    """Env for our docker calls, with a config that has no credential helper.

    Builds use public images only, but a `credsStore` in the user's config still calls its
    helper, which on macOS prompts for access on every build. So DOCKER_CONFIG points at our
    own directory, with the user's CLI plugins linked in, or buildx disappears. An explicit
    DOCKER_CONFIG is left alone.
    """
    if os.environ.get("DOCKER_CONFIG"):
        return None
    paths.DOCKER_CFG_DIR.mkdir(parents=True, exist_ok=True)
    config = paths.DOCKER_CFG_DIR / "config.json"
    if not config.is_file():
        config.write_text("{}\n")
    plugins = paths.DOCKER_CFG_DIR / "cli-plugins"
    user_plugins = Path.home() / ".docker" / "cli-plugins"
    if user_plugins.is_dir() and not plugins.exists():
        plugins.symlink_to(user_plugins)
    return dict(os.environ, DOCKER_CONFIG=str(paths.DOCKER_CFG_DIR))


def build_image(profiles, *, base=BASE_IMAGE, platform_=None):
    """Build (and load into msb) the image these profiles describe; return its ref."""
    docker = console.which("docker", "images are built with docker, then loaded into msb")
    msb = console.which("msb", "curl -fsSL https://install.microsandbox.dev | sh")
    plat = platform_ or _DOCKER_PLATFORMS.get(platform.machine().lower())
    if plat is None:
        console.die(f"unknown host arch {platform.machine()!r} — pass --platform (e.g. "
                    "linux/amd64)")
    ref = image_ref(profiles, base)
    env = docker_env()
    with tempfile.TemporaryDirectory(prefix="silkgate-build-") as tmp:
        context = Path(tmp)
        write_build_context(context, profiles, base)
        specs = ", ".join(p.image_spec for p in _image_profiles(profiles))
        console.say(f"building {ref} ({specs or 'base only'})")
        if subprocess.run([docker, "build", "--platform", plat, "-t", ref, str(context)],
                          env=env).returncode:
            console.die(f"docker build failed for {ref}")
    save = subprocess.Popen([docker, "save", ref], env=env, stdout=subprocess.PIPE)
    load = subprocess.run([msb, "load"], stdin=save.stdout)
    save.stdout.close()
    if save.wait() or load.returncode:
        console.die(f"docker save | msb load failed for {ref}")
    return ref


def ensure_image(profiles, image, *, base=BASE_IMAGE):
    """An explicit --image wins; otherwise build the profiles' image unless msb has it.

    --image beside a non-default --base is refused rather than resolved: the image is
    already chosen, so nothing is built and the base would change nothing — and a flag
    that is accepted and then ignored reads as honoured."""
    if image:
        if base != BASE_IMAGE:
            console.die("--image and --base together are contradictory: --image names the exact "
                        "image to run, so nothing is built for --base to shape — drop one")
        return image
    ref = image_ref(profiles, base)
    if image_in_msb(ref):
        return ref
    return build_image(profiles, base=base)
