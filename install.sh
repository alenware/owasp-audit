#!/usr/bin/env bash
# Instala la skill owasp-audit para Claude Code en Linux, macOS o WSL.
#
#   ./install.sh            copia la skill a ~/.claude/skills/owasp-audit
#   ./install.sh --link     crea un enlace simbólico (útil si editas la skill en este repo)
#   ./install.sh --project  instala en ./.claude/skills/owasp-audit del directorio actual
#   ./install.sh --check    solo comprueba requisitos y pasa los tests de los scripts
#
# Requisitos: bash, python3 >= 3.10 (solo biblioteca estándar). Opcional: docker o las herramientas
# de la etapa 3 (semgrep, gitleaks, osv-scanner, trivy, checkov); la skill informa lo que no encuentre.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="copy"
DEST="${HOME}/.claude/skills/owasp-audit"

for arg in "$@"; do
  case "$arg" in
    --link) MODE="link" ;;
    --project) DEST="$(pwd)/.claude/skills/owasp-audit" ;;
    --check) MODE="check" ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $arg" >&2; exit 2 ;;
  esac
done

PY="$(command -v python3 || true)"
if [[ -z "$PY" ]]; then
  echo "Falta python3 (>= 3.10)." >&2
  exit 1
fi
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || { echo "Se necesita Python >= 3.10; hay $("$PY" --version)." >&2; exit 1; }

echo "Pasando los tests de los scripts…"
(cd "$SRC" && "$PY" -I -m unittest discover -s scripts/tests -q)

if [[ "$MODE" == "check" ]]; then
  echo "Requisitos correctos. Herramientas opcionales encontradas:"
  for t in semgrep gitleaks trufflehog osv-scanner trivy checkov docker; do
    command -v "$t" >/dev/null && echo "  - $t"
  done
  exit 0
fi

if [[ "$DEST" == "$SRC" ]]; then
  echo "El origen y el destino son la misma carpeta; no hay nada que instalar."
  exit 0
fi

mkdir -p "$(dirname "$DEST")"
if [[ -e "$DEST" || -L "$DEST" ]]; then
  BACKUP="${DEST}.bak.$(date +%Y%m%d%H%M%S)"
  echo "Ya existe $DEST; lo muevo a $BACKUP"
  mv "$DEST" "$BACKUP"
fi

if [[ "$MODE" == "link" ]]; then
  ln -s "$SRC" "$DEST"
  echo "Enlace creado: $DEST -> $SRC"
else
  mkdir -p "$DEST"
  # Copia todo menos los artefactos de pruebas locales.
  tar -C "$SRC" --exclude='./.git' --exclude='*/__pycache__' --exclude='./scripts/tests/__pycache__' -cf - . | tar -C "$DEST" -xf -
  echo "Skill copiada en $DEST"
fi
echo "Listo. En Claude Code, pide por ejemplo: \"haz una auditoría OWASP de este repo\"."
