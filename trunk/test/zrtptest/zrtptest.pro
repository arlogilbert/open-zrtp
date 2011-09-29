#-------------------------------------------------
#
# Project created by QtCreator 2011-08-16T14:13:51
#
#-------------------------------------------------

QT       -= gui

TARGET = zrtptest

CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

CONFIG( debug, debug|release ) {
    OBJECTS_DIR = ./obj/debug
    DESTDIR = ./bin/debug
    DEFINES += _DEBUG
} else {
    OBJECTS_DIR = ./obj/release
    DESTDIR = ./bin/release
}

INCLUDEPATH += \
    . \
    ../ \
    ../.. \
    ../../../pjproject/pjlib/include \
    ../../../pjproject/pjlib-util/include \
    ../../../pjproject/pjmedia/include \
    ../../../pjproject/pjsip/include \
    ../../../pjproject/pjnath/include \
    ../../../pjproject/pjsip-apps/src/samples \
    ../../../pjproject/pjsip-apps/src/pjsua

win32 {
    INCLUDEPATH += \
        $$quote($(PTHREADS_ROOT)) \
        $$quote($(OPENSSL_ROOT)\\inc32) \
        $$quote($(MSDIRECTXSDK_ROOT)\\Include)
    DEFINES -= UNICODE
    HEADERS += stdafx.h
}

CONFIG( debug, debug|release ) {
    win32:LIBS += -L$$quote($(PTHREADS_ROOT)) -L$$quote($(OPENSSL_ROOT)\\out32.dbg)
    LIBS += -L../../zrtp/lib/debug
} else {
    win32:LIBS += -L$$quote($(PTHREADS_ROOT)) -L$$quote($(OPENSSL_ROOT)\\out32)
    LIBS += -L../../zrtp/lib/release
}

LIBS += \
    -L../../../pjproject\lib \
    -L../../../pjproject/pjsip/lib \
    -L../../../pjproject/pjmedia/lib \
    -L../../../pjproject/pjnath/lib \
    -L../../../pjproject/pjlib/lib \
    -L../../../pjproject/pjlib-util/lib \
    -L../../../pjproject/third_party/lib

unix:LIBS += \
    -L/usr/lib \
    -lpthread \
    -lssl \
    -lzrtp \
    -lpjsua-i686-pc-linux-gnu \
    -lpjsip-ua-i686-pc-linux-gnu \
    -lpjsip-simple-i686-pc-linux-gnu \
    -lpjsip-i686-pc-linux-gnu \
    -lpjmedia-codec-i686-pc-linux-gnu \
    -lpjmedia-i686-pc-linux-gnu \
    -lpjmedia-audiodev-i686-pc-linux-gnu \
    -lpjnath-i686-pc-linux-gnu \
    -lpjlib-util-i686-pc-linux-gnu \
    -lilbccodec-i686-pc-linux-gnu \
    -lg7221codec-i686-pc-linux-gnu \
    -lgsmcodec-i686-pc-linux-gnu \
    -lsrtp-i686-pc-linux-gnu \
    -lspeex-i686-pc-linux-gnu \
    -lresample-i686-pc-linux-gnu \
    -lportaudio-i686-pc-linux-gnu \
    -lmilenage-i686-pc-linux-gnu \
    -lpj-i686-pc-linux-gnu

win32:LIBS += \
    zrtp.lib \
    libeay32.lib \
    ssleay32.lib \
    pthreadVC2.lib \
    Iphlpapi.lib \
    ole32.lib \
    user32.lib \
    netapi32.lib \
    mswsock.lib \
    ws2_32.lib \
    gdi32.lib \
    advapi32.lib \
    kernel32.lib \
    gdi32.lib \
    winspool.lib \
    advapi32.lib \
    shell32.lib \
    oleaut32.lib \
    uuid.lib \
    odbc32.lib \
    odbccp32.lib

CONFIG( debug, debug|release ) {
    win32:LIBS += \
        libg7221codec-i386-win32-vc8-debug.lib \
        libgsmcodec-i386-win32-vc8-debug.lib \
        libilbccodec-i386-win32-vc8-debug.lib \
        libmilenage-i386-win32-vc8-debug.lib \
        libpjproject-i386-win32-vc8-debug.lib \
        libportaudio-i386-win32-vc8-debug.lib \
        libresample-i386-win32-vc8-debug.lib \
        libspeex-i386-win32-vc8-debug.lib \
        libsrtp-i386-win32-vc8-debug.lib \
        pjlib-i386-win32-vc8-debug.lib \
        pjlib-util-i386-win32-vc8-debug.lib \
        pjmedia-audiodev-i386-win32-vc8-debug.lib \
        pjmedia-codec-i386-win32-vc8-debug.lib \
        pjmedia-i386-win32-vc8-debug.lib \
        pjnath-i386-win32-vc8-debug.lib \
        pjsip-core-i386-win32-vc8-debug.lib \
        pjsip-simple-i386-win32-vc8-debug.lib \
        pjsip-ua-i386-win32-vc8-debug.lib \
        pjsua-lib-i386-win32-vc8-debug.lib
} else {
    win32:LIBS += \
        libg7221codec-i386-win32-vc8-release.lib \
        libgsmcodec-i386-win32-vc8-release.lib \
        libilbccodec-i386-win32-vc8-release.lib \
        libmilenage-i386-win32-vc8-release.lib \
        libpjproject-i386-win32-vc8-release.lib \
        libportaudio-i386-win32-vc8-release.lib \
        libresample-i386-win32-vc8-release.lib \
        libspeex-i386-win32-vc8-release.lib \
        libsrtp-i386-win32-vc8-release.lib \
        pjlib-i386-win32-vc8-release.lib \
        pjlib-util-i386-win32-vc8-release.lib \
        pjmedia-audiodev-i386-win32-vc8-release.lib \
        pjmedia-codec-i386-win32-vc8-release.lib \
        pjmedia-i386-win32-vc8-release.lib \
        pjnath-i386-win32-vc8-release.lib \
        pjsip-core-i386-win32-vc8-release.lib \
        pjsip-simple-i386-win32-vc8-release.lib \
        pjsip-ua-i386-win32-vc8-release.lib \
        pjsua-lib-i386-win32-vc8-release.lib \

}










HEADERS += \
    ../../basicqueue.h \
    ../../cond.h \
    ../../synch.h \
    ../../zTimer2.h

SOURCES += \
    base_socket.cpp \
    endpointinfotest.cpp \
    helloacktest.cpp \
    hellotest.cpp \
    main.cpp \
    main_test.cpp \
    pingtest.cpp \
    qtest.cpp \
    socket_server.cpp \
    test.cpp \
    zTest.cpp
