#!/bin/bash

set -e

echo "Starting libHy2 build process..."

# Build Configuration
PACKAGE_NAME="libHy2"
OUTPUT_DIR="./build"
AAR_NAME="libHy2"
XCFRAMEWORK_NAME="libHy2.xcframework"
MIN_SDK_VERSION="21"
TARGET_SDK_VERSION="34"
PLATFORM="android"  # default

# Java package name (can override with env var or CLI)
DEFAULT_JCLASS_PACKAGE="org.thebytearray"
JCLASS_PACKAGE="${JCLASS_PACKAGE:-$DEFAULT_JCLASS_PACKAGE}"

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -p, --platform PLATFORM    android or ios (default: android)"
    echo "  -j, --package PACKAGE      Java package name (default: $DEFAULT_JCLASS_PACKAGE)"
    echo "  -m, --min-sdk VERSION      Minimum SDK version (default: $MIN_SDK_VERSION)"
    echo "  -h, --help                Show this help message"
}

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--platform) PLATFORM="$2"; shift 2 ;;
        -j|--package) JCLASS_PACKAGE="$2"; shift 2 ;;
        -m|--min-sdk) MIN_SDK_VERSION="$2"; shift 2 ;;
        -h|--help) show_usage; exit 0 ;;
        *) print_error "Unknown option: $1"; show_usage; exit 1 ;;
    esac
done

# Validate platform
if [[ "$PLATFORM" != "android" && "$PLATFORM" != "ios" ]]; then
    print_error "Invalid platform: $PLATFORM. Must be 'android' or 'ios'"
    exit 1
fi

print_info "Build Configuration:"
print_info "  Platform: $PLATFORM"
print_info "  Package Name: $PACKAGE_NAME"
if [[ "$PLATFORM" == "android" ]]; then
    print_info "  Java Package: $JCLASS_PACKAGE"
    print_info "  Min SDK: $MIN_SDK_VERSION"
else
    print_info "  Framework Name: $XCFRAMEWORK_NAME"
fi

# Check Go
if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go."
    exit 1
fi
print_status "Go version: $(go version)"

# Check gomobile, install if missing
if ! command -v gomobile &> /dev/null; then
    print_status "Installing gomobile..."
    go install golang.org/x/mobile/cmd/gomobile@latest
fi
print_status "gomobile: $(which gomobile)"

# Initialize gomobile (will skip if already done)
gomobile init

# Create output directory
mkdir -p "$OUTPUT_DIR"

if [[ "$PLATFORM" == "android" ]]; then
    # Locate Android SDK if env vars missing
    if [ -z "$ANDROID_HOME" ] && [ -z "$ANDROID_SDK_ROOT" ]; then
        print_warning "ANDROID_HOME or ANDROID_SDK_ROOT not set. Trying common paths..."
        for path in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "/usr/local/android-sdk" "/opt/android-sdk" "/Applications/Android Studio.app/Contents/sdk"; do
            if [ -d "$path" ]; then
                export ANDROID_HOME="$path"
                export ANDROID_SDK_ROOT="$path"
                print_status "Found Android SDK at: $path"
                break
            fi
        done
    fi

    if [ -z "$ANDROID_HOME" ]; then
        print_error "Android SDK not found. Please install and set ANDROID_HOME or ANDROID_SDK_ROOT."
        exit 1
    fi
    print_status "Using Android SDK: $ANDROID_HOME"

    # Clean previous AAR
    rm -f "$OUTPUT_DIR/$AAR_NAME.aar"

    print_status "Building Android AAR..."
    gomobile bind -target=android -androidapi="$MIN_SDK_VERSION" -javapkg="$JCLASS_PACKAGE" -o "$OUTPUT_DIR/$AAR_NAME.aar" .

    if [ $? -ne 0 ]; then
        print_error "Android AAR build failed!"
        exit 1
    fi

    print_status "Build succeeded: $OUTPUT_DIR/$AAR_NAME.aar"
    ls -lh "$OUTPUT_DIR/$AAR_NAME.aar"

elif [[ "$PLATFORM" == "ios" ]]; then
    # Check Xcode
    if ! command -v xcodebuild &> /dev/null; then
        print_error "Xcode not found. Please install Xcode."
        exit 1
    fi
    print_status "Xcode version: $(xcodebuild -version | head -1)"

    # Clean previous build
    rm -rf "$OUTPUT_DIR/$XCFRAMEWORK_NAME"

    print_status "Building iOS XCFramework..."
    gomobile bind -target=ios -o "$OUTPUT_DIR/$XCFRAMEWORK_NAME" .

    if [ $? -ne 0 ]; then
        print_error "iOS XCFramework build failed!"
        exit 1
    fi

    print_status "Build succeeded: $OUTPUT_DIR/$XCFRAMEWORK_NAME"
    ls -la "$OUTPUT_DIR/$XCFRAMEWORK_NAME"
fi

print_status "Build process completed successfully."
