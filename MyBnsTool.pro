TEMPLATE = app
TARGET = MyBnsTool
QT += core xml
CONFIG += console
INCLUDEPATH += ./OpenSSL/include
HEADERS += ./BnsTool.h \
    ./Util.h
SOURCES += ./BnsTool.cpp \
    ./main.cpp \
    ./Util.cpp
RESOURCES += Resource.qrc
LIBS += ./OpenSSL/lib/libcrypto.lib