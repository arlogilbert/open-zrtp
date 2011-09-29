# -------------------------------------------------
# Project created by QtCreator 2011-08-15T15:57:49
# -------------------------------------------------

QT -= core gui

TARGET = zrtp

TEMPLATE = lib

CONFIG += staticlib

INCLUDEPATH += \
    . \
    .. \
    ../../pjproject/pjlib/include \
    ../../pjproject/pjlib-util/include \
    ../../pjproject/pjmedia/include

CONFIG( debug, debug|release ) {
    OBJECTS_DIR = ./obj/debug
    DESTDIR = ./lib/debug
    DEFINES += _DEBUG
} else {
    OBJECTS_DIR = ./obj/release
    DESTDIR = ./lib/release
}

unix:LIBS += -L/usr/lib -lssl -lpthread

win32 {
    INCLUDEPATH += \
        $$quote($(PTHREADS_ROOT)) \
        $$quote($(OPENSSL_ROOT)\\inc32)
    DEFINES -= UNICODE
    HEADERS += stdafx.h
}

HEADERS += ../zTimer2.h \
    ../zTimer.h \
    ../zTextData.h \
    ../zStateMachineDef.h \
    ../zRtpEngine.h \
    ../zRtpConfig.h \
    ../zRecord.h \
    ../zQueue.h \
    ../zPingAck.h \
    ../zPing.h \
    ../zPacketBase.h \
    ../zopenssl.h \
    ../zHelloAck.h \
    ../zHello.h \
    ../zGoClearAck.h \
    ../zGoClear.h \
    ../zErrorAck.h \
    ../zError.h \
    ../zEndpointInfo.h \
    ../zDHPart.h \
    ../zDH.h \
    ../zCryptoContext.h \
    ../zCRC32.h \
    ../zConfirm.h \
    ../zConf2Ack.h \
    ../zCommit.h \
    ../zCodes.h \
    ../zCallback.h \
    ../zAlgoSupported.h \
    ../UserCallback.h \
    ../synch.h \
    ../sRtpSecrets.h \
    ../rtp.h \
    ../pj_zrtp_transport.h \
    ../pj_zrtpadapter.h \
    ../pj_srtpadapter.h \
    ../pj_callbackadapter.h \
    ../packetQueue.h \
    ../network.h \
    ../int.h \
    ../cond.h \
    ../basicqueue.h \
    ../Base32.h

SOURCES += ../zTextData.cpp \
    ../zStateMachineDef.cpp \
    ../zRtpEngine.cpp \
    ../zRecord.cpp \
    ../zQueue.cpp \
    ../zPingAck.cpp \
    ../zPing.cpp \
    ../zopenssl.cpp \
    ../zHelloAck.cpp \
    ../zHello.cpp \
    ../zGoClearAck.cpp \
    ../zGoClear.cpp \
    ../zErrorAck.cpp \
    ../zError.cpp \
    ../zEndpointInfo.cpp \
    ../zDHPart.cpp \
    ../zDH.cpp \
    ../zCryptoContext.cpp \
    ../zCRC.cpp \
    ../zConfirm.cpp \
    ../zConf2Ack.cpp \
    ../zCommit.cpp \
    ../zAlgoSupported.cpp \
    ../pj_zrtp_transport.cpp \
    ../pj_zrtpadapter.cpp \
    ../pj_srtpadapter.cpp \
    ../pj_callbackadapter.cpp \
    ../Base32.cpp \
    ../zPacketBase.cpp

OTHER_FILES += \
    ../build_readme.txt
