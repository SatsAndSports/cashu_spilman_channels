#!/bin/bash
# Build native libraries for Go bindings distribution
#
# Usage:
#   ./scripts/build-go-libs.sh                    # Build for current platform only
#   ./scripts/build-go-libs.sh linux-amd64        # Build for specific platform
#   ./scripts/build-go-libs.sh all                # Build for all platforms (requires cross)
#
# Supported platforms:
#   linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGE_DIR="$ROOT_DIR/crates/cdk-spilman-go/packaged/lib"
CRATE_NAME="cdk-spilman-go"
LIB_NAME="libcdk_spilman_go"
STANDALONE_MANIFEST="$ROOT_DIR/Cargo.toml"

# Detect current platform
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case "$os" in
        linux) os="linux" ;;
        darwin) os="darwin" ;;
        mingw*|msys*|cygwin*) os="windows" ;;
        *) echo "Unknown OS: $os" >&2; exit 1 ;;
    esac
    
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) echo "Unknown arch: $arch" >&2; exit 1 ;;
    esac
    
    echo "${os}-${arch}"
}

# Map our platform names to Rust targets
platform_to_rust_target() {
    case "$1" in
        linux-amd64) echo "x86_64-unknown-linux-gnu" ;;
        linux-arm64) echo "aarch64-unknown-linux-gnu" ;;
        darwin-amd64) echo "x86_64-apple-darwin" ;;
        darwin-arm64) echo "aarch64-apple-darwin" ;;
        windows-amd64) echo "x86_64-pc-windows-gnu" ;;
        *) echo "Unknown platform: $1" >&2; exit 1 ;;
    esac
}

# Get library extension for platform
lib_extension() {
    case "$1" in
        linux-*) echo "a" ;;
        darwin-*) echo "a" ;;
        windows-*) echo "a" ;;  # Static lib for Windows too
    esac
}

# Build for a specific platform
build_platform() {
    local platform="$1"
    local target=$(platform_to_rust_target "$platform")
    local ext=$(lib_extension "$platform")
    local current=$(detect_platform)
    local output_dir="$PACKAGE_DIR/$platform"
    
    echo "Building for $platform (target: $target)..."
    
    mkdir -p "$output_dir"
    
    # Check if we need cross-compilation
    if [ "$platform" = "$current" ]; then
        # Native build
        echo "  Native build..."
        cargo build --profile release-smaller -p "$CRATE_NAME" --manifest-path "$STANDALONE_MANIFEST"
        
        local src="$ROOT_DIR/target/release-smaller/${LIB_NAME}.${ext}"
        local dst="$output_dir/${LIB_NAME}.${ext}"
        
        if [ ! -f "$src" ]; then
            echo "  ERROR: Built library not found at $src" >&2
            exit 1
        fi
        
        cp "$src" "$dst"
        
        # Strip the library
        echo "  Stripping..."
        if [ "$ext" = "a" ]; then
            strip --strip-debug "$dst" 2>/dev/null || true
        else
            strip "$dst" 2>/dev/null || true
        fi
        
        local size=$(ls -lh "$dst" | awk '{print $5}')
        echo "  Output: $dst ($size)"
    else
        # Cross-compilation - check for cross tool
        if ! command -v cross &> /dev/null; then
            echo "  SKIP: 'cross' not installed (needed for cross-compilation)"
            echo "  Install with: cargo install cross"
            return 1
        fi
        
        echo "  Cross-compiling with 'cross'..."
        cross build --profile release-smaller -p "$CRATE_NAME" --target "$target" --manifest-path "$STANDALONE_MANIFEST"
        
        local src="$ROOT_DIR/target/$target/release-smaller/${LIB_NAME}.${ext}"
        local dst="$output_dir/${LIB_NAME}.${ext}"
        
        if [ ! -f "$src" ]; then
            echo "  ERROR: Built library not found at $src" >&2
            exit 1
        fi
        
        cp "$src" "$dst"
        
        # Strip (may fail for cross-compiled binaries without proper toolchain)
        echo "  Stripping (may skip if cross-toolchain not available)..."
        strip --strip-debug "$dst" 2>/dev/null || true
        
        local size=$(ls -lh "$dst" | awk '{print $5}')
        echo "  Output: $dst ($size)"
    fi
}

# Main
main() {
    cd "$ROOT_DIR"
    
    local platform="${1:-}"
    
    if [ -z "$platform" ]; then
        # Build for current platform only
        platform=$(detect_platform)
        echo "Building for current platform: $platform"
        build_platform "$platform"
    elif [ "$platform" = "all" ]; then
        # Build for all platforms
        echo "Building for all platforms..."
        local platforms="linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64"
        local failed=""
        
        for p in $platforms; do
            if ! build_platform "$p"; then
                failed="$failed $p"
            fi
            echo ""
        done
        
        if [ -n "$failed" ]; then
            echo "Failed/skipped platforms:$failed"
            echo "Note: Cross-compilation requires 'cross' tool and Docker"
        fi
    else
        # Build for specific platform
        build_platform "$platform"
    fi
    
    echo ""
    echo "Done! Library files:"
    find "$PACKAGE_DIR" -name "*.a" -o -name "*.so" -o -name "*.dylib" 2>/dev/null | while read f; do
        echo "  $f ($(ls -lh "$f" | awk '{print $5}'))"
    done
}

main "$@"
