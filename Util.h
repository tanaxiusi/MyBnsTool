#pragma once
#include <QFileInfo>
#include <QList>
#include <QDir>

QFileInfoList recursiveFindFile(QDir dir);
void printLine(const QString & str);