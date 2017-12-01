#pragma once
#include <QFile>
#include <QDir>
#include <QDomNode>

class BnsTool
{
public:
	static bool extract(QFile * inFile, QDir outDir, bool convertXml);
	static bool extract64(QFile * inFile, QDir outDir, bool convertXml);
	static bool compress(QDir inDir, QFile * outFile);
	static bool compress64(QDir inDir, QFile * outFile);

	static QByteArray unpack(QByteArray bytes, qint32 unpackedSize, bool isEncrypted, bool isCompressed);
	static QByteArray pack(QByteArray bytes, bool isEncrypted, bool isCompressed, qint32 * outIntermediateCompressedSize = nullptr);

	static QByteArray xmlBin2Text(QByteArray bytes);
	static QByteArray xmlText2Bin(QByteArray bytes);

	static bool xmlAutoConvert(QFile * file);

private:
	static QDomNode parseBinXml(QIODevice * inStream, QDomDocument & document, bool isRoot = true);
	static bool serializeBinXml(QDomNode node, QIODevice * outStream, bool isRoot = true, int beginAutoId = 1, int * outEndAutoId = nullptr);
};