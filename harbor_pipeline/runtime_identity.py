"""Read installed package metadata inside built images, never Dockerfile comments."""
from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path


PYTHON_METADATA = '''import importlib.metadata as m,json
print(json.dumps({d.metadata['Name']:d.version for d in m.distributions() if d.metadata.get('Name')}))'''

NODE_METADATA = r'''
const fs=require('fs'), path=require('path');
const out={}, seen=new Set();
function visit(dir,depth) {
 if(depth>10 || !fs.existsSync(dir)) return;
 let real; try {real=fs.realpathSync(dir)} catch{return}
 if(seen.has(real)) return; seen.add(real);
 try {
   const p=JSON.parse(fs.readFileSync(path.join(dir,'package.json'),'utf8'));
   if(p.name && p.version) out[p.name]=p.version;
 } catch {}
 const nm=path.join(dir,'node_modules');
 if(fs.existsSync(nm)) for(const e of fs.readdirSync(nm)) {
   if(e.startsWith('@')) {
     for(const child of fs.readdirSync(path.join(nm,e))) visit(path.join(nm,e,child),depth+1);
   } else visit(path.join(nm,e),depth+1);
 }
}
for(const root of [process.cwd(),'/app','/opt/app','/usr/local/lib/node_modules']) visit(root,0);
console.log(JSON.stringify(out));
'''

# PHP applications often publish their release in composer.json or a VERSION
# file rather than a package-manager registry. Read both from the built image;
# the author-side source is not trusted as identity evidence.
PHP_METADATA = r'''
$out = [];
$roots = ["/app", "/opt/app", "/var/www/html", "/var/www"];
foreach ($roots as $root) {
    $composer = $root . "/composer.json";
    if (is_file($composer)) {
        $j = json_decode(@file_get_contents($composer), true);
        if (is_array($j) && !empty($j["name"])) {
            if (!empty($j["version"])) $out[$j["name"]] = $j["version"];
            $out["__app_name"] = $j["name"];
        }
    }
    foreach (["VERSION", "version.txt", "version.php"] as $name) {
        $path = $root . "/" . $name;
        if (!is_file($path)) continue;
        $text = trim(@file_get_contents($path, false, null, 0, 4096));
        if ($text !== "" && strlen($text) < 120) $out["__app_version"] = $text;
    }
    foreach (glob($root . "/vendor/composer/installed.json") ?: [] as $path) {
        $j = json_decode(@file_get_contents($path), true);
        $packages = $j["packages"] ?? $j;
        if (!is_array($packages)) continue;
        foreach ($packages as $pkg) {
            if (!empty($pkg["name"]) && !empty($pkg["version"])) {
                $out[$pkg["name"]] = $pkg["version"];
            }
        }
    }
}
echo json_encode($out);
'''


def _same_version(left: object, right: object) -> bool:
    def norm(value: object) -> str:
        text = str(value or "").strip()
        return text[1:] if text[:1] in {"v", "V"} else text

    return bool(left) and norm(left) == norm(right)


def inspect_runtime(
    image: str, *, runner, product=None, product_ref=None, log_path=None
) -> dict:
    probes = [
        "python -I -c " + shlex.quote(PYTHON_METADATA),
        "python3 -I -c " + shlex.quote(PYTHON_METADATA),
        "node -e " + shlex.quote(NODE_METADATA),
        "php -r " + shlex.quote(PHP_METADATA),
    ]
    packages = {}
    methods = []
    errors = []
    for command in probes:
        result = runner(image, command, timeout=60, max_output=500000)
        if result.get("exit") != 0:
            errors.append(str(result.get("output", ""))[-300:])
            continue
        try:
            parsed = json.loads(str(result.get("output") or "").strip())
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            packages.update({str(k): str(v) for k, v in parsed.items() if isinstance(v, str)})
            methods.append(command.split()[0])
    from .dataset import canonical_project
    app_name = str(packages.pop("__app_name", "") or "")
    app_version = str(packages.pop("__app_version", "") or "")
    if (
        product
        and product_ref
        and not any(canonical_project(name) == canonical_project(product) for name in packages)
        and app_version
        and _same_version(app_version, product_ref)
    ):
        segments = {
            canonical_project(part)
            for part in app_name.lstrip("@").replace(":", "/").split("/")
            if part
        }
        # A root composer project or a VERSION file is runtime source evidence,
        # not a package registry digest. Require the declared release to match
        # the ref the image was built from.
        if not app_name or canonical_project(product) in segments:
            packages[product] = app_version
            methods.append("php-app-version")
    if product and not any(canonical_project(name) == canonical_project(product) for name in packages):
        binary_packages, binary_methods = inspect_binaries(image, runner=runner)
        packages.update(binary_packages)
        methods.extend(binary_methods)
    report = {
        "method": "installed-package-and-binary-metadata",
        "image": image,
        "dependencies": packages,
        "collectors": methods,
        "errors": errors,
        "verified": bool(packages),
    }
    if log_path is not None:
        from .util import write_json
        write_json(log_path, report)
    return report


def parse_go_metadata(text: str) -> dict[str, str]:
    packages = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0] in {"mod", "dep"} and parts[2] != "(devel)":
            packages[parts[1]] = parts[2].removeprefix("v")
    return packages


def jar_metadata(path: Path) -> dict[str, str]:
    packages = {}
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist()[:10000]:
            if not item.filename.endswith("/pom.properties") or item.file_size > 65536:
                continue
            values = {}
            for line in archive.read(item).decode("utf-8", "replace").splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip()
            if all(values.get(key) for key in ("groupId", "artifactId", "version")):
                packages[f"{values['groupId']}:{values['artifactId']}"] = values["version"]
    return packages


def inspect_binaries(image: str, *, runner) -> tuple[dict, list]:
    """Read JAR and Go metadata without executing copied application binaries.

    Go's cross-platform `go version -m` reads build information; it never runs
    the application. A missing inspector yields missing evidence, not a pin.
    """
    from .backend import docker_binary
    from .util import no_window_kwargs
    result = runner(image, "find /app /opt/app /usr/local/bin -maxdepth 5 -type f \\( -name '*.jar' -o -perm /111 \\) -print 2>/dev/null", timeout=60, max_output=20000)
    paths = [line for line in str(result.get("output", "")).splitlines() if line.startswith(("/app/", "/opt/app/", "/usr/local/bin/"))]
    if not paths:
        return {}, []
    docker = docker_binary()
    created = subprocess.run([docker, "create", "--entrypoint", "/bin/true", image], capture_output=True, text=True, timeout=30, **no_window_kwargs())
    if created.returncode:
        return {}, []
    cid = created.stdout.strip()
    packages, methods = {}, []
    try:
        with tempfile.TemporaryDirectory(prefix="harbor-identity-") as directory:
            for index, source in enumerate(paths[:32]):
                if not source.endswith(".jar") and not shutil.which("go"):
                    continue
                destination = Path(directory) / str(index)
                copied = subprocess.run([docker, "cp", f"{cid}:{source}", str(destination)], capture_output=True, timeout=60, **no_window_kwargs())
                if copied.returncode or not destination.is_file() or destination.is_symlink():
                    continue
                if source.endswith(".jar"):
                    try:
                        packages.update(jar_metadata(destination))
                        methods.append("jar-pom.properties")
                    except (OSError, zipfile.BadZipFile):
                        pass
                else:
                    parsed = subprocess.run([shutil.which("go"), "version", "-m", str(destination)], capture_output=True, text=True, timeout=15, **no_window_kwargs())
                    found = parse_go_metadata(parsed.stdout)
                    if found:
                        packages.update(found)
                        methods.append("go-buildinfo")
    finally:
        subprocess.run([docker, "rm", "-f", cid], capture_output=True, timeout=30, **no_window_kwargs())
    return packages, sorted(set(methods))
