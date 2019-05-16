# myseo

PROJECT_NAME = ntl

NTL_SOURCE_FILE = \
	src/FFT.c \
	src/FacVec.c \
	src/GF2.c \
	src/GF2E.c \
	src/GF2EX.c \
	src/GF2EXFactoring.c \
	src/GF2X.c \
	src/GF2X1.c \
	src/GF2XFactoring.c \
	src/GF2XVec.c \
	src/HNF.c \
	src/ctools.c \
	src/LLL.c \
	src/LLL_FP.c \
	src/LLL_QP.c \
	src/LLL_RR.c \
	src/LLL_XD.c \
	src/RR.c \
	src/WordVector.c \
	src/ZZ.c \
	src/ZZVec.c \
	src/ZZX.c \
	src/ZZX1.c \
	src/ZZXCharPoly.c \
	src/ZZXFactoring.c \
	src/ZZ_p.c \
	src/ZZ_pE.c \
	src/ZZ_pEX.c \
	src/ZZ_pEXFactoring.c \
	src/ZZ_pX.c \
	src/ZZ_pX1.c \
	src/ZZ_pXCharPoly.c \
	src/ZZ_pXFactoring.c \
	src/fileio.c \
	src/lip.c \
	src/lzz_p.c \
	src/lzz_pE.c \
	src/lzz_pEX.c \
	src/lzz_pEXFactoring.c \
	src/lzz_pX.c \
	src/lzz_pX1.c \
	src/lzz_pXCharPoly.c \
	src/lzz_pXFactoring.c \
	src/mat_GF2.c \
	src/mat_GF2E.c \
	src/mat_RR.c \
	src/mat_ZZ.c \
	src/mat_ZZ_p.c \
	src/mat_ZZ_pE.c \
	src/mat_lzz_p.c \
	src/mat_lzz_pE.c \
	src/mat_poly_ZZ.c \
	src/mat_poly_ZZ_p.c \
	src/mat_poly_lzz_p.c \
	src/quad_float.c \
	src/tools.c \
	src/vec_GF2.c \
	src/vec_GF2E.c \
	src/vec_RR.c \
	src/vec_ZZ.c \
	src/vec_ZZ_p.c \
	src/vec_ZZ_pE.c \
	src/vec_lzz_p.c \
	src/vec_lzz_pE.c \
	src/xdouble.c \
	src/G_LLL_FP.c \
	src/G_LLL_QP.c \
	src/G_LLL_XD.c \
	src/G_LLL_RR.c \
	src/GetPID1.c \
	src/thread.c \
	src/BasicThreadPool.c

STATIC_LIBRARY_FILE = lib$(PROJECT_NAME).a

NTL_OBJECT_FILE     += $(NTL_SOURCE_FILE:.c=.o)
LIBRARY_OBJECT_FILE += $(NTL_OBJECT_FILE)

#armv7 armv7s arm64
#ARCH     ?= armv7
#PLATFORM ?= iPhoneOS

#SDKVERSION ?= 12.2
#DEVELOPER  ?= /Applications/Xcode.app/Contents/Developer
#DEVROOT ?= ${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer
#SDKROOT ?= ${DEVROOT}/SDKs/${PLATFORM}${SDKVERSION}.sdk
#BUILD_TOOLS ?= ${DEVELOPER}

#CXX    ?= xcrun -sdk iphoneos ${BUILD_TOOLS}/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++
#AR     ?= xcrun -sdk iphoneos ${BUILD_TOOLS}/Toolchains/XcodeDefault.xctoolchain/usr/bin/ar
#RANLIB ?= xcrun -sdk iphoneos ${BUILD_TOOLS}/Toolchains/XcodeDefault.xctoolchain/usr/bin/ranlib

#CXXFLAGS += -arch ${ARCH} -isysroot ${SDKROOT}
#LDFLAGS  += -arch ${ARCH} -isysroot ${SDKROOT}

CXXFLAGS += -g -O2 -x c++ -fPIC -W -Wall -Wno-unused-parameter -fexceptions -fno-rtti -fno-exceptions -fvisibility=hidden -fstrict-aliasing -Wa,--noexecstack -ffunction-sections -funwind-tables -fstack-protector -fno-short-enums -Bdynamic

INC_PATHS += -I./include -I./include/NTL

all: clean lib 

%.o: %.c
	$(CXX) -c $(CXXFLAGS) $(INC_PATHS) -o $@ $<

lib: $(LIBRARY_OBJECT_FILE)
	$(AR) cru $(STATIC_LIBRARY_FILE) $(LIBRARY_OBJECT_FILE)
	$(RANLIB) $(STATIC_LIBRARY_FILE)

clean:
	@rm -rf $(LIBRARY_OBJECT_FILE) $(STATIC_LIBRARY_FILE)
