#include <QCoreApplication>
#include <QtDebug>
#include <QTextCodec>
#include <iostream>
#include "BnsTool.h"
#include "Util.h"

void printHelp()
{
	QFile file(":/help.txt");
	file.open(QIODevice::ReadOnly);
	QString helpText = QString::fromUtf8(file.readAll());
	std::cout << helpText.toLocal8Bit().data();
}

int main(int argc, char *argv[])
{
	QCoreApplication app(argc, argv);

	QStringList argumentList = app.arguments();
	argumentList.removeFirst();
	if (argumentList.size() < 2)
	{
		printHelp();
		return 0;
	}

	const QString instruction = argumentList.at(0);
	if (instruction == "-e" || instruction == "-x" || instruction == "-e64" || instruction == "-x64")
	{
		const bool convertXml = (instruction == "-x") || (instruction == "-x64");
		const bool is64 = instruction.endsWith("64");
		const QString inFileName = argumentList.at(1);
		const QString outDirName = (argumentList.size() >= 3) ? argumentList.at(2) : (inFileName + ".files");
		if(is64)
			BnsTool::extract64(&QFile(inFileName), QDir(outDirName), convertXml);
		else
			BnsTool::extract(&QFile(inFileName), QDir(outDirName), convertXml);
	}
	else if (instruction == "-c" || instruction == "-c64")
	{
		const QString inDirName = argumentList.at(1);
		const bool is64 = instruction.endsWith("64");
		const QString associatedOutFileName = inDirName.endsWith(".files") ? inDirName.left(inDirName.length() - 6) : QString();
		const QString outFileName = (argumentList.size() >= 3) ? argumentList.at(2) : associatedOutFileName;
		if (outFileName.size() > 0)
		{
			if(is64)
				BnsTool::compress64(QDir(inDirName), &QFile(outFileName));
			else
				BnsTool::compress(QDir(inDirName), &QFile(outFileName));
		}else
		{
			printLine(QString("%1 is not regular dir name, you should enter a out file").arg(inDirName));
		}
	}
	else if (instruction == "-s")
	{
		const QString fileName = argumentList.at(1);
		BnsTool::xmlAutoConvert(&QFile(fileName));
	}
	else
	{
		printHelp();
	}
}
