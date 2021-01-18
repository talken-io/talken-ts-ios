#!/bin/bash

if [ ! -f boost_1_69_0/tools/build/src/user-config.jam ]; then
	cp ../user-config.jam tools/build/src/user-config.jam
fi
if [ ! -f boost_1_69_0/tools/build/src/tools/darwin.jam ]; then
	cp ../darwin.jam tools/build/src/tools/darwin.jam
fi

#./bootstrap.sh --with-libraries=atomic,chrono,date_time,exception,filesystem,graph,iostreams,math,program_options,random,regex,serialization,signals,system,test,thread,wave
./bootstrap.sh --with-libraries=iostreams,program_options,serialization,random,regex,system

# clean and build for iOS, j option is num of cores x 1.5
rm -fr ios-build
mkdir ios-build
./b2 -j6 --build-dir=ios-build --stagedir=ios-build/armv7 toolset=darwin-armv7 architecture=arm instruction-set=armv7 address-model=32 target-os=iphone threading=multi link=static stage
./b2 -j6 --build-dir=ios-build --stagedir=ios-build/armv7s toolset=darwin-armv7s architecture=arm instruction-set=armv7s address-model=32 target-os=iphone threading=multi link=static stage
./b2 -j6 --build-dir=ios-build --stagedir=ios-build/arm64 toolset=darwin-arm64 architecture=arm address-model=64 target-os=iphone threading=multi link=static stage
#./b2 -j6 --build-dir=ios-build --stagedir=ios-build/i386 toolset=darwin-i386 architecture=x86 address-model=32 target-os=iphone threading=multi link=static stage
#./b2 -j6 --build-dir=ios-build --stagedir=ios-build/x86_64 toolset=darwin-x86_64 architecture=x86 address-model=64 target-os=iphone threading=multi link=static stage

# create libboost.a archive for each architecture
cd ios-build
xcrun --sdk iphoneos ar crus armv7/libboost.a boost/bin.v2/libs/*/build/darwin-armv7/release/instruction-set-armv7/link-static/target-os-iphone/threading-multi/*/*.o
xcrun --sdk iphoneos ar crus armv7s/libboost.a boost/bin.v2/libs/*/build/darwin-armv7s/release/instruction-set-armv7s/link-static/target-os-iphone/threading-multi/*/*.o
xcrun --sdk iphoneos ar crus arm64/libboost.a boost/bin.v2/libs/*/build/darwin-arm64/release/link-static/target-os-iphone/threading-multi/*/*.o
#xcrun --sdk iphoneos ar crus i386/libboost.a boost/bin.v2/libs/*/build/darwin-i386/release/link-static/target-os-iphone/threading-multi/*/*.o
#xcrun --sdk iphoneos ar crus x86_64/libboost.a boost/bin.v2/libs/*/build/darwin-x86_64/release/link-static/target-os-iphone/threading-multi/*/*.o

# create FAT libboost.a archive
mkdir -p lib
/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/lipo \
	-arch armv7   "armv7/libboost.a" \
	-arch armv7s  "armv7s/libboost.a" \
	-arch arm64   "arm64/libboost.a" \
	-output       "lib/libboost.a" \
	-create 
#	-arch i386    "i386/libboost.a" \
#	-arch x86_64  "x86_64/libboost.a" \

# create link for include folder
#mkdir include
#cp -a ../boost include


VERSION_TYPE=Alpha
FRAMEWORK_NAME=boost
FRAMEWORK_VERSION=A
FRAMEWORKDIR=.

FRAMEWORK_CURRENT_VERSION=1.62.0
FRAMEWORK_COMPATIBILITY_VERSION=1.62.0
FRAMEWORK_BUNDLE=${FRAMEWORKDIR}/${FRAMEWORK_NAME}.framework

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
cp  lib/libboost.a ${FRAMEWORK_INSTALL_NAME}

echo "Framework: Copying includes..."
cp -r ../${FRAMEWORK_NAME}/*  ${FRAMEWORK_BUNDLE}/Headers/
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

cd ..
