#include "Util.h"
#include <iostream>

QFileInfoList recursiveFindFile(QDir dir)
{
	QFileInfoList result;
	for (const QFileInfo & fileInfo : dir.entryInfoList())
	{
		if (fileInfo.fileName() == "." || fileInfo.fileName() == "..")
			continue;
		if (fileInfo.isFile())
			result << fileInfo;
		else if (fileInfo.isDir())
			result << recursiveFindFile(QDir(fileInfo.filePath()));
	}
	return result;
}

void printLine(const QString & str)
{
	std::cout << str.toLocal8Bit().data() << "\n";
}
