#include "BnsTool.h"
#include <QtEndian>
#include <QBuffer>
#include <QtDebug>
#include <QDomDocument>
#include "openssl/aes.h"
#include "Util.h"

static const quint8 CryptKeyText[16] = { 'b', 'n', 's', '_', 'o', 'b', 't', '_', 'k', 'r', '_', '2', '0', '1', '4', '#' };

static AES_KEY aesEncryptKey;
static AES_KEY aesDecryptKey;

static int globalInit()
{
	AES_set_encrypt_key(CryptKeyText, sizeof(CryptKeyText) * 8, &aesEncryptKey);
	AES_set_decrypt_key(CryptKeyText, sizeof(CryptKeyText) * 8, &aesDecryptKey);
	return 0;
}

static const int init_dummy = globalInit();

#pragma pack(push, 1)
template<int intSize>
struct DatFileHeader
{
	typedef typename QIntegerForSize<intSize>::Signed qintX;

	quint8 signature[8];
	qint32 version;
	quint8 unknown1[5];
	qintX totalFileIntermediateSize;
	qintX fileCount;
	bool isCompressed;
	bool isEncrypted;
	quint8 unknown2[62];
	qintX packedFileTableSize;
	qintX unpackedFileTableSize;

	void init()
	{
		memset(this, 0, sizeof(DatFileHeader));
		memcpy(signature, "UOSEDALB", 8);
		version = 2;
	}

	bool check()
	{
		return memcmp(signature, "UOSEDALB", 8) == 0 && version == 2
			&& (fileCount > 0 && fileCount < 10000) && packedFileTableSize <= unpackedFileTableSize;
	}
};

template<int intSize>
struct DatFileTableItem
{
	typedef typename QIntegerForSize<intSize>::Signed qintX;

	quint8 unknown1;
	bool isCompressed;
	bool isEncrypted;
	quint8 unknown2;
	qintX unpackedSize;
	qintX intermediateSize;		// 压缩后加密前的大小，向上取整后就是下面的packedSize
	qintX packedSize;
	qintX dataOffset;
	quint8 padding[60];
};

struct BinXmlHeader
{
	quint8 signature[8];
	qint32 version;
	qint32 fileSize;
	quint8 padding[64];
	quint8 unknown1;

	void init()
	{
		memset(this, 0, sizeof(BinXmlHeader));
		memcpy(signature, "LMXBOSLB", 8);
		version = 3;
		unknown1 = 1;
	}
};
#pragma pack(pop)

static void xor (quint8 * buffer, int size)
{
	static const quint8 XorKey[] = { 0xA4, 0x9F, 0xD8, 0xB3, 0xF6, 0x8E, 0x39, 0xC2, 0x2D, 0xE0, 0x61, 0x75, 0x5C, 0x4B, 0x1A, 0x07 };
	for (int i = 0; i < size; ++i)
		buffer[i] ^= XorKey[i % sizeof(XorKey)];
}

static int getPaddedSize(int size, int base)
{
	return ((size - 1) / base + 1) * base;
}

template <class T>
static T streamRead(QIODevice * inStream)
{
	T var = T();
	inStream->read((char*)&var, sizeof(T));
	return var;
}

template <class T>
static bool streamWrite(QIODevice * outStream, const T & value)
{
	return sizeof(value) == outStream->write((const char*)&value, sizeof(value));
}

static QString streamReadString(QIODevice * inStream, int length)
{
	QByteArray bytes = inStream->read(length * 2);
	return QString::fromUtf16((const char16_t *)bytes.data(), bytes.size() / 2);
}

template <int intSize>
static QString streamAutoReadString(QIODevice * inStream, bool useXor, int * outLength = nullptr)
{
	int length = streamRead<QIntegerForSize<intSize>::Signed>(inStream);
	QString result = streamReadString(inStream, length);
	if(useXor)
		xor ((quint8*)result.data(), result.length() * 2);
	if (outLength)
		*outLength = result.length();
	return result;
}

static bool streamWriteString(QIODevice * outStream, const QString & str)
{
	const int bytesToWrite = str.length() * 2;
	return bytesToWrite == outStream->write((const char*)str.data(), bytesToWrite);
}

template <int intSize>
static bool streamAutoWriteString(QIODevice * outStream, const QString & str, bool useXor)
{
	const int length = str.length();
	if (!streamWrite<QIntegerForSize<intSize>::Signed>(outStream, length))
		return false;
	const int bytesToWrite = length * 2;
	int bytesWritten = 0;
	if (useXor)
	{
		QByteArray temp((const char*)str.data(), bytesToWrite);
		xor ((quint8*)temp.data(), bytesToWrite);
		bytesWritten = outStream->write(temp.data(), bytesToWrite);
	}
	else
	{
		bytesWritten = outStream->write((const char*)str.data(), bytesToWrite);
	}
	return bytesWritten == bytesToWrite;
}

template <int intSize>
bool extract(QFile * inFile, QDir outDir, bool convertXml)
{
	typedef typename QIntegerForSize<intSize>::Signed qintX;

	if (!inFile)
		return false;
	printLine(QString("Extracting %1 to %2").arg(inFile->fileName()).arg(outDir.path()));

	if (!inFile->isOpen())
		inFile->open(QIODevice::ReadOnly);
	if (!inFile->isOpen())
	{
		printLine("Error! file open failed");
		return false;
	}
	inFile->seek(0);

	if (!outDir.exists())
		outDir.mkdir(".");

	DatFileHeader<intSize> header = { 0 };
	inFile->read((char*)&header, sizeof(header));
	if (inFile->atEnd())
		return false;

	if (!header.check())
	{
		printLine(QString("Error! corrupted header"));
		return false;
	}

	const QByteArray packedFileTable = inFile->read(header.packedFileTableSize);
	const qintX dataBeginPos = streamRead<qintX>(inFile);
	if (dataBeginPos != inFile->pos())
		printLine(QString("Warning! error data begin position at %1").arg(inFile->pos() - intSize));

	QByteArray fileTable = BnsTool::unpack(packedFileTable, header.unpackedFileTableSize, header.isEncrypted, header.isCompressed);

	QBuffer fileTableStream(&fileTable);
	fileTableStream.open(QIODevice::ReadOnly);

	int actualTotalFileIntermediateSize = 0;
	for (int i = 0; i < header.fileCount; ++i)
	{
		if(fileTableStream.atEnd())
			break;

		QString relativeFilePath = streamAutoReadString<intSize>(&fileTableStream, false);
		DatFileTableItem<intSize> fileItem = { 0 };
		fileTableStream.read((char*)&fileItem, sizeof(fileItem));

		actualTotalFileIntermediateSize += fileItem.intermediateSize;

		printLine(QString("%1 / %2  %3").arg(i + 1).arg(header.fileCount).arg(relativeFilePath));

		inFile->seek(dataBeginPos + fileItem.dataOffset);
		QByteArray storedPackedFile = inFile->read(fileItem.packedSize);
		QByteArray unpackedFile = BnsTool::unpack(storedPackedFile, fileItem.unpackedSize, fileItem.isEncrypted, fileItem.isCompressed);

		if (convertXml && relativeFilePath.endsWith(".xml", Qt::CaseInsensitive) && unpackedFile.startsWith("LMXBOSLB"))
			unpackedFile = BnsTool::xmlBin2Text(unpackedFile);

		QString physicalFilePath = outDir.filePath(relativeFilePath);
		QDir fileDir = QFileInfo(physicalFilePath).dir();
		if (!fileDir.exists())
			fileDir.mkpath(".");
		
		QFile file(physicalFilePath);
		if (file.open(QIODevice::WriteOnly | QIODevice::Truncate))
			file.write(unpackedFile);
		else
			printLine(QString("Warning! file %1 open failed").arg(relativeFilePath));
	}

	if(actualTotalFileIntermediateSize != header.totalFileIntermediateSize)
		printLine(QString("Warning! error recorded sum size"));

	printLine("Extract finished");

	return true;
}

template <int intSize>
bool compress(QDir inDir, QFile * outFile)
{
	typedef typename QIntegerForSize<intSize>::Signed qintX;

	if (!outFile)
		return false;
	printLine(QString("Compressing %1 to %2").arg(inDir.path()).arg(outFile->fileName()));

	if (!outFile->isOpen())
		outFile->open(QIODevice::WriteOnly);
	if (!outFile->isOpen())
	{
		printLine("Error! file open failed");
		return false;
	}
	outFile->seek(0);

	QFileInfoList fileInfoList = recursiveFindFile(inDir);
	
	DatFileHeader<intSize> header;
	header.init();
	header.fileCount = fileInfoList.size();
	header.isCompressed = true;
	header.isEncrypted = true;

	QBuffer fileTableStream;
	QBuffer fileDataStream;

	fileTableStream.open(QIODevice::WriteOnly);
	fileDataStream.open(QIODevice::WriteOnly);

	for(int i = 0; i < fileInfoList.size(); ++i)
	{
		const QFileInfo & fileInfo = fileInfoList.at(i);
		const QString physicalFilePath = fileInfo.filePath();
		const QString relativeFilePath = inDir.relativeFilePath(fileInfo.absoluteFilePath()).replace("/", "\\");
		printLine(QString("%1 / %2  %3").arg(i + 1).arg(header.fileCount).arg(relativeFilePath));

		QFile file(physicalFilePath);
		if (!file.open(QIODevice::ReadOnly))
		{
			printLine(QString("Warning! file %1 open failed").arg(relativeFilePath));
			continue;
		}
		QByteArray fileData = file.readAll();
		file.close();

		if (relativeFilePath.endsWith(".xml", Qt::CaseInsensitive) && fileData.startsWith("<?xml"))
			fileData = BnsTool::xmlText2Bin(fileData);

		qint32 intermediateCompressedSize = 0;
		QByteArray packedFileData = BnsTool::pack(fileData, true, true, &intermediateCompressedSize);

		DatFileTableItem<intSize> fileItem = { 0 };
		fileItem.unknown1 = 2;
		fileItem.isCompressed = true;
		fileItem.isEncrypted = true;
		fileItem.unpackedSize = fileData.size();
		fileItem.intermediateSize = intermediateCompressedSize;
		fileItem.packedSize = packedFileData.size();
		fileItem.dataOffset = fileDataStream.pos();

		streamAutoWriteString<intSize>(&fileTableStream, relativeFilePath, false);
		fileTableStream.write((const char*)&fileItem, sizeof(fileItem));

		fileDataStream.write(packedFileData);

		header.totalFileIntermediateSize += intermediateCompressedSize;
	}

	fileTableStream.close();
	fileDataStream.close();

	QByteArray fileTable = fileTableStream.data();
	QByteArray packedFileTable = BnsTool::pack(fileTable, true, true);
	QByteArray fileData = fileDataStream.data();
	
	header.unpackedFileTableSize = fileTable.size();
	header.packedFileTableSize = packedFileTable.size();

	fileTable.clear();
	fileTableStream.setData(QByteArray());
	fileDataStream.setData(QByteArray());

	outFile->write((const char*)&header, sizeof(header));
	outFile->write(packedFileTable);
	streamWrite<qintX>(outFile, (qintX)(sizeof(header) + packedFileTable.size() + intSize));
	outFile->write(fileData);

	printLine(QString("Compress finished, %1 bytes").arg(outFile->size()));
	return true;
}

bool BnsTool::extract(QFile * inFile, QDir outDir, bool convertXml)
{
	return ::extract<4>(inFile, outDir, convertXml);
}

bool BnsTool::extract64(QFile * inFile, QDir outDir, bool convertXml)
{
	return ::extract<8>(inFile, outDir, convertXml);
}

bool BnsTool::compress(QDir inDir, QFile * outFile)
{
	return ::compress<4>(inDir, outFile);
}

bool BnsTool::compress64(QDir inDir, QFile * outFile)
{
	return ::compress<8>(inDir, outFile);
}

QByteArray BnsTool::unpack(QByteArray bytes, qint32 unpackedSize, bool isEncrypted, bool isCompressed)
{
	QByteArray result;
	const int headerSize = isCompressed ? 4 : 0;
	if (isEncrypted)
	{
		const int paddedSize = getPaddedSize(bytes.size(), AES_BLOCK_SIZE);
		result.resize(headerSize + paddedSize);
		memcpy(result.data() + headerSize, bytes.data(), bytes.size());
		memset(result.data() + headerSize + bytes.size(), 0, paddedSize - bytes.size());
		for (int i = 0; i < paddedSize; i += AES_BLOCK_SIZE)
		{
			unsigned char * bufferPtr = (unsigned char*)(result.data() + headerSize + i);
			AES_decrypt(bufferPtr, bufferPtr, &aesDecryptKey);
		}
	}
	else
	{
		if (headerSize > 0)
			result = QByteArray(headerSize, '\0') + bytes;
		else
			result = bytes;
	}

	if (isCompressed)
	{
		*(qint32*)result.data() = qToBigEndian(unpackedSize);
		result = qUncompress(result);
	}

	return result;
}

QByteArray BnsTool::pack(QByteArray bytes, bool isEncrypted, bool isCompressed, qint32 * outIntermediateCompressedSize)
{
	QByteArray result;
	int headerSize = 0;
	if (isCompressed)
	{
		result = qCompress(bytes);
		headerSize = 4;
	}
	else
	{
		result = bytes;
	}

	if (outIntermediateCompressedSize)
		*outIntermediateCompressedSize = result.size() - headerSize;

	if (isEncrypted)
	{
		const int actualSize = result.size() - headerSize;
		const int paddedSize = getPaddedSize(actualSize, AES_BLOCK_SIZE);
		if (result.size() < paddedSize + headerSize)
			result += QByteArray(paddedSize + headerSize - result.size(), '\0');
		
		for (int i = 0; i < paddedSize; i += AES_BLOCK_SIZE)
		{
			unsigned char * inPtr = (unsigned char*)(result.data() + headerSize + i);
			unsigned char * outPtr = (unsigned char*)(result.data() + i);
			AES_encrypt(inPtr, outPtr, &aesEncryptKey);
		}
		result.chop(headerSize);
		headerSize = 0;
	}
	if (headerSize > 0)
	{
		result.remove(0, headerSize);
		headerSize = 0;
	}
	return result;
}

bool BnsTool::xmlAutoConvert(QFile * file)
{
	if (!file)
		return false;
	printLine(QString("Auto converting %1").arg(file->fileName()));
	if (!file->isOpen())
		file->open(QIODevice::ReadWrite);
	if (!file->isOpen())
	{
		printLine("Error! file open failed");
		return false;
	}
	file->seek(0);
	QByteArray header = file->read(8);
	QByteArray bytes;
	if(header.startsWith("<?xml"))
	{
		printLine("Text to bin");
		file->seek(0);
		bytes = xmlText2Bin(file->readAll());
	}
	else if (header.startsWith("LMXBOSLB"))
	{
		printLine("Bin to text");
		file->seek(0);
		bytes = xmlBin2Text(file->readAll());
	}
	else
	{
		printLine("Unknown file type");
		return false;
	}

	if (bytes.size() > 0)
	{
		file->seek(0);
		file->write(bytes);
		file->resize(bytes.size());
		printLine(QString("Convert finished %1 bytes").arg(bytes.size()));
		return true;
	}
	else
	{
		printLine("Error converting");
		return false;
	}
}

QByteArray BnsTool::xmlBin2Text(QByteArray bytes)
{
	QBuffer stream(&bytes);
	stream.open(QIODevice::ReadOnly);
	BinXmlHeader header = { 0 };
	stream.read((char*)&header, sizeof(header));

	if (stream.atEnd())
		return QByteArray();

	QString originalFilePath = streamAutoReadString<4>(&stream, true);

	QDomDocument document;
	QDomProcessingInstruction processingInstruction = document.createProcessingInstruction("xml version=\"1.0\"", "encoding=\"utf-8\"");
	QDomComment commentNode = document.createComment(originalFilePath);
	QDomNode rootNode = parseBinXml(&stream, document);

	rootNode.insertBefore(commentNode, rootNode.firstChild());

	document.appendChild(processingInstruction);
	document.appendChild(rootNode);

	return document.toByteArray(2);
}

QByteArray BnsTool::xmlText2Bin(QByteArray bytes)
{
	QDomDocument document;
	QString errorMsg;
	if (!document.setContent(bytes, &errorMsg))
	{
		printLine(QString("Error parsing xml \"%1\"").arg(errorMsg));
		return QByteArray();
	}

	QString originalFilePath;
	
	QDomElement rootNode = document.documentElement();
	const QDomNode firstChildNode = rootNode.firstChild();
	if (firstChildNode.nodeType() == QDomNode::CommentNode)
	{
		originalFilePath = firstChildNode.nodeValue();
		rootNode.removeChild(firstChildNode);
	}
	else
	{
		printLine(QString("Warning! Xml no comment"));
	}

	QBuffer stream;
	stream.open(QIODevice::WriteOnly);

	BinXmlHeader header = { 0 };
	stream.write((const char*)&header, sizeof(header));
	streamAutoWriteString<4>(&stream, originalFilePath, true);
	serializeBinXml(rootNode, &stream);

	header.init();
	header.fileSize = stream.size();
	stream.seek(0);
	stream.write((const char*)&header, sizeof(header));
	stream.close();

	return stream.data();
}

QDomNode BnsTool::parseBinXml(QIODevice * inStream, QDomDocument & document, bool isRoot)
{
	QDomNode node;
	if (inStream->atEnd())
		return node;

	qint32 nodeType = 1;
	if (!isRoot)
		nodeType = streamRead<qint32>(inStream);
	
	if (nodeType != 1 && nodeType != 2)
	{
		printLine(QString("Error node type"));
		return node;
	}

	if (nodeType == 1)
	{
		QDomElement elementNode = document.createElement("tempName");
		const qint32 attributeCount = streamRead<qint32>(inStream);
		for (int i = 0; i < attributeCount; ++i)
		{
			const QString key = streamAutoReadString<4>(inStream, true);
			const QString value = streamAutoReadString<4>(inStream, true);
			elementNode.setAttribute(key, value);
		}
		quint8 unknown1 = streamRead<quint8>(inStream);
		const QString tagName = streamAutoReadString<4>(inStream, true);
		elementNode.setTagName(tagName);
		node = elementNode;
	}
	else if (nodeType == 2)
	{
		QDomText textNode = document.createTextNode("tempName");
		QString text = streamAutoReadString<4>(inStream, true);
		quint8 unknown1 = streamRead<quint8>(inStream);
		const QString tagName = streamAutoReadString<4>(inStream, true);
		if (text.trimmed().length() > 0)
		{
			textNode.setData(text);
			node = textNode;
		}
	}

	const qint32 childNodeCount = streamRead<qint32>(inStream);
	const qint32 autoId = streamRead<qint32>(inStream);

	for (int i = 0; i < childNodeCount; ++i)
	{
		const QDomNode childNode = parseBinXml(inStream, document, false);
		if (!childNode.isNull())
			node.appendChild(childNode);
	}

	return node;
}

bool BnsTool::serializeBinXml(QDomNode node, QIODevice * outStream, bool isRoot, int beginAutoId, int * outEndAutoId)
{
	QDomNode::NodeType nodeType = node.nodeType();
	QString tagName;
	if (nodeType == QDomNode::ElementNode)
	{
		if (!isRoot)
			streamWrite<qint32>(outStream, 1);
		const QDomElement elementNode = node.toElement();
		const QDomNamedNodeMap attributes = elementNode.attributes();
		streamWrite<qint32>(outStream, attributes.count());
		for (int i = 0; i < attributes.count(); ++i)
		{
			const QDomAttr attrNode = attributes.item(i).toAttr();
			streamAutoWriteString<4>(outStream, attrNode.name(), true);
			streamAutoWriteString<4>(outStream, attrNode.value(), true);
		}
		tagName = elementNode.tagName();
	}
	else if (nodeType == QDomNode::TextNode)
	{
		if (!isRoot)
			streamWrite<qint32>(outStream, 2);
		const QDomText textNode = node.toText();
		const QString text = textNode.nodeValue();
		streamAutoWriteString<4>(outStream, text, true);
		tagName = "text";
	}
	else
	{
		printLine(QString("Unsupported node type at line %1").arg(node.lineNumber()));
		return false;
	}
	QDomNodeList childNodeList = node.childNodes();

	int autoId = beginAutoId;

	streamWrite<quint8>(outStream, 1);
	streamAutoWriteString<4>(outStream, tagName, true);
	streamWrite<quint32>(outStream, childNodeList.size());
	streamWrite<quint32>(outStream, autoId);

	autoId++;
	for(int i = 0; i < childNodeList.size(); ++i)
		serializeBinXml(childNodeList.at(i), outStream, false, autoId, &autoId);
	
	return true;
}