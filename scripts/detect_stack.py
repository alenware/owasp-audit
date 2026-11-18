#!/usr/bin/env python3
"""Etapa 1: detecta lenguajes, frameworks, IaC, CI, uso de LLM/agentes y herramientas instaladas.

Uso:
    python detect_stack.py <repo> [--out inventory-stack.json]

Solo lee archivos (nunca ejecuta nada del repo) y consulta el PATH para saber qué herramientas existen.
La salida alimenta scope.json (catálogos activos) y la etapa 3 (qué herramientas se pueden correr).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import utf8_stdout, write_json  # noqa: E402

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__", "dist", "build", ".next",
             "target", ".terraform", ".idea", ".vscode", "coverage", ".owasp-audit", ".mypy_cache", ".pytest_cache"}
MAX_FILES = 50_000

LANG_EXT = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".java": "java", ".kt": "kotlin", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".rs": "rust", ".swift": "swift", ".scala": "scala", ".c": "c", ".cpp": "cpp",
    ".dart": "dart", ".ex": "elixir", ".sql": "sql",
}

# patrón de dependencia -> (categoría, etiqueta)
DEP_SIGNALS = {
    r"^express$": ("framework", "express"), r"^fastify$": ("framework", "fastify"), r"^koa$": ("framework", "koa"),
    r"^@nestjs/core$": ("framework", "nestjs"), r"^next$": ("framework", "nextjs"), r"^hono$": ("framework", "hono"),
    r"^flask$": ("framework", "flask"), r"^django$": ("framework", "django"), r"^fastapi$": ("framework", "fastapi"),
    r"^spring-boot": ("framework", "spring-boot"), r"^github\.com/gin-gonic/gin": ("framework", "gin"),
    r"^github\.com/labstack/echo": ("framework", "echo"), r"^rails$": ("framework", "rails"), r"^laravel/framework$": ("framework", "laravel"),
    r"^graphql$|^apollo-server|^@apollo/server$|^graphene$|^strawberry-graphql$": ("api", "graphql"),
    r"^openai$": ("llm", "openai"), r"^anthropic$|^@anthropic-ai/sdk$": ("llm", "anthropic"),
    r"^@anthropic-ai/claude-agent-sdk$|^claude-agent-sdk$": ("agent", "claude-agent-sdk"),
    r"^langchain|^@langchain/": ("llm", "langchain"), r"^llama[-_]index|^llamaindex$": ("llm", "llamaindex"),
    r"^ai$|^@ai-sdk/": ("llm", "vercel-ai-sdk"), r"^google-genai$|^@google/genai$|^google-generativeai$": ("llm", "gemini"),
    r"^mistralai$|^@mistralai/": ("llm", "mistral"), r"^ollama$": ("llm", "ollama"), r"^transformers$": ("llm", "transformers"),
    r"^@modelcontextprotocol/sdk$|^mcp$|^fastmcp$": ("agent", "mcp"), r"^crewai$|^autogen|^langgraph|^@langchain/langgraph$": ("agent", "agent-framework"),
    r"^chromadb$|^pinecone|^@pinecone-database/|^weaviate|^qdrant|^pgvector$|^faiss": ("llm", "vector-store"),
    r"^jsonwebtoken$|^jose$|^pyjwt$|^python-jose$": ("auth", "jwt"), r"^passport": ("auth", "passport"),
    r"^next-auth$|^@auth/": ("auth", "authjs"), r"^bcrypt|^argon2": ("auth", "password-hashing"),
    r"^stripe$": ("payments", "stripe"), r"^@supabase/supabase-js$|^supabase$": ("data", "supabase"),
    r"^prisma$|^@prisma/client$|^sequelize$|^typeorm$|^mongoose$|^sqlalchemy$|^drizzle-orm$": ("data", "orm"),
}

TOOLS = ["semgrep", "codeql", "gitleaks", "trufflehog", "osv-scanner", "trivy", "grype", "syft", "checkov", "bandit",
         "gosec", "zap.sh", "zap-baseline.py", "nuclei", "schemathesis", "promptfoo", "garak", "docker", "npm", "pip-audit"]


def walk(root: Path):
    count = 0
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
            continue
        if p.is_file():
            count += 1
            if count > MAX_FILES:
                return
            yield p


def deps_from_manifests(root: Path, files: list[Path]) -> set[str]:
    deps: set[str] = set()
    for f in files:
        name = f.name
        try:
            if name == "package.json":
                pj = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    deps.update((pj.get(key) or {}).keys())
            elif name in ("requirements.txt", "requirements-dev.txt") or (name.startswith("requirements") and name.endswith(".txt")):
                for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    m = re.match(r"\s*([A-Za-z0-9_.\-\[\]]+)", line)
                    if m and not line.strip().startswith(("#", "-")):
                        deps.add(m.group(1).split("[")[0].lower())
            elif name == "pyproject.toml" or name == "Pipfile":
                deps.update(x.lower() for x in re.findall(r'["\']?([A-Za-z0-9_.\-]+)\s*(?:[<>=~!\[]|["\']\s*=)', f.read_text(encoding="utf-8", errors="replace")))
            elif name == "go.mod":
                deps.update(re.findall(r"^\s*(?:require\s+)?([a-z0-9.\-]+/[^\s]+)\s+v", f.read_text(encoding="utf-8", errors="replace"), re.M))
            elif name in ("pom.xml", "build.gradle", "build.gradle.kts"):
                deps.update(re.findall(r"(spring-boot[a-z\-]*)", f.read_text(encoding="utf-8", errors="replace")))
            elif name == "Gemfile":
                deps.update(re.findall(r"gem\s+['\"]([^'\"]+)", f.read_text(encoding="utf-8", errors="replace")))
            elif name == "composer.json":
                cj = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                deps.update((cj.get("require") or {}).keys())
        except (OSError, ValueError):
            continue
    return deps


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    root = args.repo.resolve()
    if not root.is_dir():
        print(f"No es una carpeta: {root}", file=sys.stderr)
        return 2

    files = list(walk(root))
    rel = [f.relative_to(root).as_posix() for f in files]
    langs = Counter(LANG_EXT[f.suffix.lower()] for f in files if f.suffix.lower() in LANG_EXT)

    manifests = [f for f in files if f.name in {"package.json", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod",
                                                   "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "composer.json"}
                 or (f.name.startswith("requirements") and f.suffix == ".txt")]
    deps = deps_from_manifests(root, manifests)
    signals: dict[str, set[str]] = {}
    for dep in deps:
        for pat, (cat, label) in DEP_SIGNALS.items():
            if re.search(pat, dep, re.IGNORECASE):
                signals.setdefault(cat, set()).add(label)

    lockfiles = [r for r in rel if Path(r).name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
                                                    "Pipfile.lock", "uv.lock", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock"}]
    iac = {
        "dockerfile": [r for r in rel if Path(r).name.lower().startswith("dockerfile")],
        "compose": [r for r in rel if re.search(r"(docker-)?compose[^/]*\.ya?ml$", r)],
        "terraform": [r for r in rel if r.endswith(".tf")],
        "helm": [r for r in rel if Path(r).name == "Chart.yaml"],
        "kubernetes": [],
    }
    for f in files:
        if f.suffix in (".yaml", ".yml") and "workflows" not in f.parts:
            try:
                head = f.read_text(encoding="utf-8", errors="replace")[:2000]
            except OSError:
                continue
            if re.search(r"^apiVersion:", head, re.M) and re.search(r"^kind:\s*(Deployment|Pod|Service|Ingress|StatefulSet|DaemonSet|CronJob|Role|ClusterRole)", head, re.M):
                iac["kubernetes"].append(f.relative_to(root).as_posix())
    ci = {
        "github_actions": [r for r in rel if r.startswith(".github/workflows/")],
        "gitlab": [r for r in rel if r == ".gitlab-ci.yml"],
        "other": [r for r in rel if r in ("Jenkinsfile", "azure-pipelines.yml", ".circleci/config.yml", "bitbucket-pipelines.yml")],
    }
    mobile = [r for r in rel if Path(r).name in ("AndroidManifest.xml", "Info.plist") or r.endswith(".xcodeproj/project.pbxproj")]
    openapi = [r for r in rel if re.search(r"(openapi|swagger)[^/]*\.(ya?ml|json)$", r, re.IGNORECASE)]
    mcp_configs = [r for r in rel if Path(r).name in (".mcp.json", "mcp.json", "claude_desktop_config.json")]
    env_files = [r for r in rel if re.match(r"(.*/)?\.env(\..+)?$", r) and not r.endswith((".example", ".sample", ".template"))]

    uses_llm = bool(signals.get("llm") or signals.get("agent") or mcp_configs)
    catalogs = ["top10_web_2025", "api_top10_2023"]
    if uses_llm:
        catalogs.append("llm_top10_2025")
    if signals.get("agent") or mcp_configs:
        catalogs.append("agentic_top10_2026")
    if mobile:
        catalogs.append("mobile_top10_2024")
    if iac["kubernetes"] or iac["helm"]:
        catalogs.append("kubernetes_top10_2025")
    if any(ci.values()):
        catalogs.append("cicd_top10")
    if env_files or any(ci.values()):
        catalogs.append("nhi_top10_2025")

    top_level = sorted({p.split("/")[0] for p in rel if "/" in p})
    result = {
        "repo": str(root),
        "file_count": len(files),
        "truncated": len(files) >= MAX_FILES,
        "top_level_dirs": top_level,
        "top_level_files": sorted(p for p in rel if "/" not in p),
        "languages": dict(langs.most_common()),
        "signals": {k: sorted(v) for k, v in sorted(signals.items())},
        "manifests": [f.relative_to(root).as_posix() for f in manifests],
        "lockfiles": lockfiles,
        "missing_lockfile": bool(manifests) and not lockfiles,
        "iac": {k: v for k, v in iac.items() if v},
        "ci": {k: v for k, v in ci.items() if v},
        "openapi_specs": openapi,
        "mobile": mobile,
        "mcp_configs": mcp_configs,
        "committed_env_files": env_files,
        "tools_available": {t: bool(shutil.which(t)) for t in TOOLS},
        "suggested_catalogs": catalogs,
        "suggested_llm_mode": uses_llm,
    }
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        write_json(args.out, result)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
