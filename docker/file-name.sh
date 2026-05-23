#!/bin/sh
os="mihomo-linux-"
case $TARGETPLATFORM in
    "linux/amd64")
        arch="amd64-v1"
        ;;
    "linux/386")
        arch="386"
        ;;
    "linux/arm64")
        arch="arm64"
        ;;
    "linux/arm/v7")
        arch="armv7"
        ;;
    "linux/riscv64")
        arch="riscv64"
        ;;
    *)
        echo "Unknown architecture"
        exit 1
        ;;        
esac
file_name="$os$arch-$(cat bin/version.txt)"
if [ -f "bin/$file_name.gz" ]; then
    echo "$file_name"
    exit 0
fi
legacy_file_name="mihomo-legacy-$os$arch-$(cat bin/version.txt)"
if [ -f "bin/$legacy_file_name.gz" ]; then
    echo "$legacy_file_name"
    exit 0
fi
echo "$file_name"
