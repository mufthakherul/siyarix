#!/bin/bash
set -euo pipefail

# ================================================================
# Siyarix APT Repository Builder
# Creates a proper apt repository with Release + InRelease files
# For Debian/Ubuntu/Kali Linux
# ================================================================

REPO_DIR="packages/deb/apt-repo"
GPG_KEY="${GPG_KEY:-}"
PKG_VERSION="${1:-1.0.0}"

echo "==> Building APT repository at ${REPO_DIR}"

# Ensure we have a .deb to add
DEB_FILE="siyarix_${PKG_VERSION}_all.deb"
if [ ! -f "${DEB_FILE}" ]; then
  echo "==> Building .deb first..."
  bash packages/deb/build-deb.sh "${PKG_VERSION}"
fi

# Copy .deb into pool for each distro
for dist in stable kali; do
  mkdir -p "${REPO_DIR}/pool/${dist}/"
  mkdir -p "${REPO_DIR}/dists/${dist}/main/binary-amd64/"
  cp "${DEB_FILE}" "${REPO_DIR}/pool/${dist}/"
done

# Generate Packages files
for dist in stable kali; do
  echo "==> Generating Packages for ${dist}"
  dpkg-scanpackages --multiversion \
    "${REPO_DIR}/pool/${dist}/" \
    > "${REPO_DIR}/dists/${dist}/main/binary-amd64/Packages"
  gzip -9kf "${REPO_DIR}/dists/${dist}/main/binary-amd64/Packages"
done

# Generate Release files
for dist in stable kali; do
  echo "==> Generating Release for ${dist}"
  cd "${REPO_DIR}/dists/${dist}"

  cat > Release << EOF
Origin: Siyarix
Label: Siyarix APT Repository
Suite: ${dist}
Codename: ${dist}
Version: ${PKG_VERSION}
Date: $(date -Ru)
Architectures: amd64 arm64
Components: main
Description: Siyarix AI Cybersecurity Orchestration Agent APT Repository
EOF

  # Generate hashes
  echo "MD5Sum:" >> Release
  for f in $(find main -type f | sort); do
    echo " $(md5sum "${f}" | cut -d' ' -f1) $(stat -c%s "${f}") ${f}" >> Release
  done
  echo "SHA256:" >> Release
  for f in $(find main -type f | sort); do
    echo " $(sha256sum "${f}" | cut -d' ' -f1) $(stat -c%s "${f}") ${f}" >> Release
  done

  # Sign Release
  if [ -n "${GPG_KEY}" ]; then
    gpg --default-key "${GPG_KEY}" --armor --detach-sign --output Release.gpg Release
    gpg --default-key "${GPG_KEY}" --clearsign --output InRelease Release
  else
    echo "==> WARNING: No GPG_KEY set. Creating unsigned Release (InRelease skipped)."
    echo "    Set GPG_KEY env var to sign the repository."
  fi

  echo "==> Release for ${dist} generated at ${REPO_DIR}/dists/${dist}/"
  cd ../../..
done

echo "==> APT repository ready at ${REPO_DIR}"
echo "==> To serve: cd ${REPO_DIR} && python3 -m http.server 8080"
echo "==> To use: echo 'deb [signed-by=/usr/share/keyrings/siyarix.gpg] http://your-server/apt stable main' | sudo tee /etc/apt/sources.list.d/siyarix.list"
