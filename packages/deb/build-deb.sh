#!/bin/bash
set -euo pipefail

# ================================================================
# Siyarix .deb Builder
# Builds a standalone .deb package for Debian/Ubuntu/Kali Linux
# ================================================================

PKG_NAME="siyarix"
PKG_VERSION="${1:-1.0.1}"
BUILD_DIR="build/deb/${PKG_NAME}_${PKG_VERSION}_all"
DEB_FILE="${PKG_NAME}_${PKG_VERSION}_all.deb"

echo "==> Building ${PKG_NAME} ${PKG_VERSION} .deb package"

# Clean
rm -rf "${BUILD_DIR}" "${DEB_FILE}"

# Create package structure
mkdir -p "${BUILD_DIR}/DEBIAN"
mkdir -p "${BUILD_DIR}/usr/bin"
mkdir -p "${BUILD_DIR}/usr/lib/${PKG_NAME}"
mkdir -p "${BUILD_DIR}/usr/share/${PKG_NAME}"
mkdir -p "${BUILD_DIR}/usr/share/doc/${PKG_NAME}"
mkdir -p "${BUILD_DIR}/etc/${PKG_NAME}"

# Copy control files
cp packages/deb/DEBIAN/control "${BUILD_DIR}/DEBIAN/"
sed -i "s/Version:.*/Version: ${PKG_VERSION}/" "${BUILD_DIR}/DEBIAN/control"
cp packages/deb/DEBIAN/postinst "${BUILD_DIR}/DEBIAN/"
cp packages/deb/DEBIAN/prerm "${BUILD_DIR}/DEBIAN/"
chmod 755 "${BUILD_DIR}/DEBIAN/postinst" "${BUILD_DIR}/DEBIAN/prerm"

# Create launcher script
cat > "${BUILD_DIR}/usr/bin/siyarix" << 'LAUNCHER'
#!/bin/bash
exec python3 -m siyarix "$@"
LAUNCHER
chmod 755 "${BUILD_DIR}/usr/bin/siyarix"

# Copy source code
cp -r src/siyarix "${BUILD_DIR}/usr/lib/${PKG_NAME}/"
cp pyproject.toml "${BUILD_DIR}/usr/share/${PKG_NAME}/"
cp README.md "${BUILD_DIR}/usr/share/${PKG_NAME}/"
cp LICENSE "${BUILD_DIR}/usr/share/doc/${PKG_NAME}/"

# Create .pth file for Python path
mkdir -p "${BUILD_DIR}/usr/lib/python3/dist-packages"
echo "/usr/lib/${PKG_NAME}" > "${BUILD_DIR}/usr/lib/python3/dist-packages/${PKG_NAME}.pth"

# Create conffiles
cat > "${BUILD_DIR}/etc/${PKG_NAME}/config.yaml" << 'CONF'
# Siyarix system configuration
theme: default
CONF
echo "/etc/${PKG_NAME}/config.yaml" > "${BUILD_DIR}/DEBIAN/conffiles"

# Build .deb
fakeroot dpkg-deb --build "${BUILD_DIR}" "${DEB_FILE}"

echo "==> Built: ${DEB_FILE}"
echo "==> Install: sudo dpkg -i ${DEB_FILE}"
echo "==> Or add apt repo (see docs):"
echo "    curl -fsSL https://siyarix.github.io/apt/KEY.gpg | sudo gpg --dearmor -o /usr/share/keyrings/siyarix.gpg"
echo "    echo 'deb [signed-by=/usr/share/keyrings/siyarix.gpg] https://siyarix.github.io/apt stable main' | sudo tee /etc/apt/sources.list.d/siyarix.list"
echo "    sudo apt update && sudo apt install siyarix"
