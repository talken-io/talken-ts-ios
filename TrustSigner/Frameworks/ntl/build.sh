#!/bin/bash

# mySeo

CURRENTPATH=`pwd`
SDKVERSION=`xcrun -sdk iphoneos --show-sdk-version`
IOS_MIN_SDK_VERSION="8.0"
DEVELOPER=`xcode-select -print-path`
#ARCHS="armv7 armv7s arm64 i386 x86_64"
ARCHS="armv7 armv7s arm64"
PLATFORM="iPhoneOS"

make clean
rm -rf output
mkdir output

for ARCH in ${ARCHS}
do
	echo "Building Library ntl for ${PLATFORM} ${SDKVERSION} ${ARCH}"

	export DEVROOT="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
	export SDKROOT="${DEVROOT}/SDKs/${PLATFORM}${SDKVERSION}.sdk"
	export BUILD_TOOLS="${DEVELOPER}"

	export CC="xcrun -sdk iphoneos ${BUILD_TOOLS}/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc"
	export CXX="xcrun -sdk iphoneos ${BUILD_TOOLS}/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++"
	export AR="xcrun -sdk iphoneos ${BUILD_TOOLS}/Toolchains/XcodeDefault.xctoolchain/usr/bin/ar"
	export RANLIB="xcrun -sdk iphoneos ${BUILD_TOOLS}/Toolchains/XcodeDefault.xctoolchain/usr/bin/ranlib"
    export CFLAGS="-arch ${ARCH} -pipe -no-cpp-precomp -isysroot ${SDKROOT}"
    export CXXFLAGS="-arch ${ARCH} -pipe -no-cpp-precomp -isysroot ${SDKROOT}"
	export LDFLAGS="-arch ${ARCH} -pipe -no-cpp-precomp -isysroot ${SDKROOT}"

	make
	cp libntl.a output/libntl-${ARCH}.a
	make clean
done

/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/lipo \
	-arch armv7   "output/libntl-armv7.a" \
	-arch armv7s  "output/libntl-armv7s.a" \
	-arch arm64   "output/libntl-arm64.a" \
	-output       "output/libntl.a" \
	-create
#	-arch i386    "output/libntl-i386.a" \
#	-arch x86_64  "output/libntl-x86_64.a" \



cd output
VERSION_TYPE=Alpha
FRAMEWORK_NAME=ntl
FRAMEWORK_VERSION=A
FRAMEWORKDIR=.

FRAMEWORK_CURRENT_VERSION=1.62.0
FRAMEWORK_COMPATIBILITY_VERSION=1.62.0
FRAMEWORK_BUNDLE=${FRAMEWORKDIR}/${FRAMEWORK_NAME}.framework

echo "Making Framework for ${FRAMEWORK_BUNDLE}"

rm -rf ${FRAMEWORK_BUNDLE}

mkdir -p ${FRAMEWORK_BUNDLE}
mkdir -p ${FRAMEWORK_BUNDLE}/Versions
mkdir -p ${FRAMEWORK_BUNDLE}/Versions/${FRAMEWORK_VERSION}
mkdir -p ${FRAMEWORK_BUNDLE}/Versions/${FRAMEWORK_VERSION}/Resources
mkdir -p ${FRAMEWORK_BUNDLE}/Versions/${FRAMEWORK_VERSION}/Headers
mkdir -p ${FRAMEWORK_BUNDLE}/Versions/${FRAMEWORK_VERSION}/Documentation

ln -s $FRAMEWORK_VERSION               ${FRAMEWORK_BUNDLE}/Versions/Current
ln -s Versions/Current/Headers         ${FRAMEWORK_BUNDLE}/Headers
ln -s Versions/Current/Resources       ${FRAMEWORK_BUNDLE}/Resources
ln -s Versions/Current/Documentation   ${FRAMEWORK_BUNDLE}/Documentation
ln -s Versions/Current/$FRAMEWORK_NAME ${FRAMEWORK_BUNDLE}/$FRAMEWORK_NAME

FRAMEWORK_INSTALL_NAME=${FRAMEWORK_BUNDLE}/Versions/${FRAMEWORK_VERSION}/${FRAMEWORK_NAME}
cp  libntl.a ${FRAMEWORK_INSTALL_NAME}

echo "Framework: Copying includes..."
cp -r ../include/NTL/*  ${FRAMEWORK_BUNDLE}/Headers/
cat > ${FRAMEWORK_BUNDLE}/Resources/Info.plist <<InfoplistEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>English</string>
    <key>CFBundleExecutable</key>
    <string>${FRAMEWORK_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>${FRAMEWORK_NAME}.org</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleSignature</key>
    <string>????</string>
    <key>CFBundleVersion</key>
    <string>${FRAMEWORK_CURRENT_VERSION}</string>
  </dict>
</plist>
InfoplistEOF

echo "Done: ${FRAMEWORK_BUNDLE}"
