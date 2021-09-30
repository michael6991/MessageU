#include "Client.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>



/*		
*		Client ctor.
*		Attempt to read from ME_INFO file if exists and obtain its information
*		regarding the user.
* 
*		A RSA public key consists in several (big) integer values,
*		and a RSA private key consists in also some integer values.
*		Though the contents differ, a RSA public keyand the corresponding
*		RSA private key share a common mathematical structure, and,
*		in particular, both include a specific value called the modulus.
*		The publicand private key of a given pair necessarily work over the same modulus value,
*		otherwise RSA does not work
*		(what it encrypted with a public key must be decrypted with the corresponding private key).
*/
Client::Client(boost::asio::io_context& io_context) : io_context_(io_context), socket_(io_context)
{
	getServerInfo();

	// create a client according to me.info file
	if (boost::filesystem::exists(ME_INFO))
	{
		// readout the username, UUID and private key
		parseInfoFile(ME_INFO);

		// decode base 64 private key that was read from file
		privateKey = Base64Wrapper::decode(base64Pivatekey);

		// initialize the rsa private engine using the existing private key
		rsapriv = new RSAPrivateWrapper(privateKey);

		// generate the corresponding public key according to the existing private key
		rsapriv->getPublicKey(publicKey.data(), PUB_KEY_SIZE);

		// create RSA encryptor
		rsapub = new RSAPublicWrapper(publicKey.data(), PUB_KEY_SIZE);


		std::cout << "Client's username: " << username << std::endl;
		std::cout << "\nClient's UUID:" << std::endl;
		hexify((unsigned char*)clientID.data(), UUID_SIZE);
	}

	// create a new client entirely
	else
	{
		// create the rsa private engine
		rsapriv = new RSAPrivateWrapper();

		// retrieve the private key generated on the creation of the RSAPrivateWrapper
		privateKey = rsapriv->getPrivateKey();

		// encode it as base64
		base64Pivatekey = Base64Wrapper::encode(privateKey);

		// generate the public key from the existing private key
		rsapriv->getPublicKey(publicKey.data(), PUB_KEY_SIZE);

		// create RSA encryptor
		rsapub = new RSAPublicWrapper(publicKey.data(), PUB_KEY_SIZE);

		/*
		std::cout << "\nPublic Key" << std::endl;
		hexify((unsigned char*)publicKey.data(), PUB_KEY_SIZE);
		std::cout << "\nPrivate Key Raw" << std::endl;
		hexify((unsigned char*)privateKey.c_str(), privateKey.length());
		std::cout << "\nPrivate Key (base64)" << std::endl;
		std::cout << base64Pivatekey << std::endl;
		*/
	}
}




Client::~Client()
{
	delete(rsapriv);
	delete(rsapub);
}





/*
* Connect to server and set timeouts on I/O operations
*/
void Client::do_connect()
{
	socket_.connect(tcp::endpoint(ip_, port_));
	configureTimeouts();
}


/*
* Set timeouts on send and receive (I/O) operations of the connected socket
*/
void Client::configureTimeouts()
{
	// older method:
	//const int timeout = TIMEOUT;  // milliseconds
	//::setsockopt(socket_.native_handle(), SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
	//::setsockopt(socket_.native_handle(), SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

	// newer method:
	socket_.set_option(rcv_timeout_option{ RCV_TIMEOUT });
	socket_.set_option(snd_timeout_option{ SND_TIMEOUT });
}


/*
* Registration to the MessageU network.
*
* 1.Request user name from the user via cin/stdin, and send to the server.
* server will ignore clientID field in the header.
*
* 2.Server will respond with uuid.
*
* 3.Client will save the user name and the uuid into the me.info text file.
* first row for user name, second row for uuid.
* Client will save the private key generated erlier to the third row of me.info in base 64 encoding.
*
* if me.info file already exists, client will terminate registration.
*/
void Client::handleRegistration()
{
	if (boost::filesystem::exists(ME_INFO))
		throw std::exception("Error, client already registered");


	username = getUserNameFromUser(MAX_ALLOWED_USERNAME);

	/* 1. construct request header and send */
	std::vector<char>header = buildHeader(clientID.data(),
		version,
		REGISTER_CODE,
		MAX_ALLOWED_USERNAME + PUB_KEY_SIZE);

	do_connect();

	// send header
	sendBytes(header, HEADER_SIZE);

	// convert string username to bytes vector and send, then send public key
	std::vector<char> vec(username.c_str(), username.c_str() + MAX_ALLOWED_USERNAME);
	sendBytes(vec.data(), MAX_ALLOWED_USERNAME);
	sendBytes(publicKey.data(), PUB_KEY_SIZE);


	/* 2. receive response */
	// receive response
	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);

	if (resHead->statusCode == SERVER_ERROR_CODE && resHead->payloadSize != UUID_SIZE) {
		delete(resHead);
		std::cout << "Did not receive UUID from server: " << data << std::endl;
		throw std::exception("Server responded with an error");
	}
	std::cout << "Server status code: " << resHead->statusCode << std::endl;


	recvBytes(UUID_SIZE);
	memcpy(clientID.data(), data, UUID_SIZE);
	std::cout << "UUID: "; hexify((unsigned char*)clientID.data(), UUID_SIZE); std::cout << std::endl;
	delete(resHead);


	/* 3. save to me.info */
	std::ofstream me = openOutFile(ME_INFO);
	std::cout << "Creating: " << ME_INFO << std::endl;
	me << username << std::endl;
	me << hex2Ascii(clientID.data(), UUID_SIZE) << std::endl;
	me << base64Pivatekey << std::endl;
	me.close();
}


/*
* Request for list of all clients in MessageU network and print it.
* notice that even though you can create a fake me.info file to bypass
* the simple file existance if statement, you cannot fake the uuid.
* Hence, when the server will receive your fake uuid, it attempt to search it.
* Almost 100% of the time it would not find your uuid in the clients DB and
* return an error.
*/
void Client::handleClientsList()
{
	if (!boost::filesystem::exists(ME_INFO))
		throw std::exception("Error, client not registered");


	std::vector<char>header = buildHeader(clientID.data(),
		version,
		CLIENTS_LIST_CODE,
		0);

	do_connect();

	// send header
	sendBytes(header, HEADER_SIZE);


	// receive response header + uuid
	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);
	recvBytes(UUID_SIZE);

	if (resHead->statusCode == SERVER_ERROR_CODE) {
		delete(resHead);
		throw std::exception("Server responded with an error");
	}
	std::cout << "Server status code: " << resHead->statusCode << std::endl;


	// continue to receiving the response payload
	uint32_t numClients = resHead->payloadSize / (UUID_SIZE + MAX_ALLOWED_USERNAME);
	std::cout << "Total number of clients: " << numClients << std::endl;



	// no other clients registered
	if (resHead->payloadSize == 0)
		return;


	char usr[MAX_ALLOWED_USERNAME] = "";
	uuid cid = { 0 };

	for (uint32_t i = 0; i < numClients; i++)
	{
		recvBytes(UUID_SIZE);
		memcpy(cid.data(), data, UUID_SIZE);

		recvBytes(MAX_ALLOWED_USERNAME);
		memcpy(usr, data, MAX_ALLOWED_USERNAME);
		std::string usr_str(usr);

		std::cout << i << ") Name: " << usr_str << std::endl;
		std::cout << "	UUID: "; hexify((unsigned char*)cid.data(), UUID_SIZE);


		// add uuid and username to map
		usernameToUuidMap.insert({ usr_str, cid });
		uuidToUsernameMap.insert({ cid, usr_str });
	}
	delete(resHead);
}



/*
* Get from user the uuid of client that we want to receive the public key.
* Refer as: "other client" along the code.
* Send the uuid to server and receive back the public key if this user exists.
*/
void Client::handlePublicKeyRequest()
{
	if (!boost::filesystem::exists(ME_INFO))
		throw std::exception("Error, client not registered");


	std::vector<char>header = buildHeader(clientID.data(),
		version,
		PUBLIC_KEY_CODE,
		UUID_SIZE);


	// get destination client's uuid from its username
	std::string destUsername = getUserNameFromUser(MAX_ALLOWED_USERNAME);
	std::map<std::string, uuid>::iterator it = usernameToUuidMap.find(destUsername);
	if (it == usernameToUuidMap.end())
		throw std::exception("Username not found, aborting.");
	
	uuid destClientId = it->second;



	do_connect();

	// send header and destionation client's uuid
	sendBytes(header, HEADER_SIZE);
	sendBytes(destClientId.data(), UUID_SIZE);


	// receive response header + uuid
	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);
	recvBytes(UUID_SIZE);

	if (resHead->statusCode == SERVER_ERROR_CODE) {
		delete(resHead);
		throw std::exception("Server responded with an error");
	}
	std::cout << "Server status code: " << resHead->statusCode << std::endl;


	// receive public key of destination client
	recvBytes(PUB_KEY_SIZE);
	pubKey destClientPubKey = { 0 };
	memcpy(destClientPubKey.data(), data, PUB_KEY_SIZE);

	
	// assign to class member
	destCidToPubKeyMap.insert({ destClientId, destClientPubKey });


	std::cout << "Received public key of client" << std::endl;
	//hexify((unsigned char*)destClientId.data(), UUID_SIZE);
	delete(resHead);
}



/*
* Pull waiting messages from server one by one and act accordingly
* to the received message type.
*/
void Client::handlRequestForWaitingMessages()
{
	if (!boost::filesystem::exists(ME_INFO))
		throw std::exception("Error, client not registered");


	
	// construct header
	std::vector<char>header = buildHeader(clientID.data(),
		version,
		WAITING_MESSAGES_CODE,
		0);



	do_connect();


	// send header
	sendBytes(header, HEADER_SIZE);


	// receive response header + uuid
	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);
	recvBytes(UUID_SIZE);

	if (resHead->statusCode == SERVER_ERROR_CODE) {
		delete(resHead);
		throw std::exception("Server responded with an error");
	}
	std::cout << "Server status code: " << resHead->statusCode << std::endl;


	Message* msg = new Message;
	uint32_t total = resHead->payloadSize;
	uint32_t sum = 0;



	std::cout << "\nPulling Waiting Messages" << std::endl;
	std::cout << "---------------" << std::endl;


	while (sum < total)  // or socket timeout
	{
		recvAndParseMessageHeader(msg);

		switch (msg->msgType)
		{
		case SYMMETRIC_KEY_REQUEST_MSG_TYPE:
			sum += getRequestForSymmetricKey(msg);
			break;

		case SYMMETRIC_KEY_SEND_MSG_TYPE:
			sum += getSymmetricKey(msg);
			break;

		case TEXT_SEND_MSG_TYPE:
			sum += getTextMsg(msg);
			break;

		case FILE_SEND_MSG_TYPE:
			sum += getFileMsg(msg);
			break;

		default:
			throw std::exception("Wrong message type received");
			break;
		}
	}
	delete(resHead);  // release memory allocation
}



/*
* Send ecrypted text to destination client
*/
void Client::handleSendTextMessage()
{
	if (!boost::filesystem::exists(ME_INFO))
		throw std::exception("Error, client not registered");


	// get destination client's uuid from its username
	std::string destUsername = getUserNameFromUser(MAX_ALLOWED_USERNAME);
	std::map<std::string, uuid>::iterator it = usernameToUuidMap.find(destUsername);
	if (it == usernameToUuidMap.end())
		throw std::exception("Username not found, aborting.");
	uuid destClientId = it->second;


	
	// check if key-exchage was performed with destination client
	symKey symmetricKey = { 0 };
	isValidKey(destClientId, &symmetricKey);



	// get content
	std::string content = getInputFromUser("Enter message, max allowed chars (including NULL) is ", MAX_MSG_LEN);

	
	// encrypt content
	AESWrapper aes((unsigned char *)symmetricKey.data(), SYMMETRIC_KEY_SIZE);
	std::string cipher = aes.encrypt(content.c_str(), content.length());



	// construct header and message payload	
	std::vector<char>header = buildHeader(
		clientID.data(),
		version,
		SEND_MESSAGE_CODE,
		UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE + cipher.length());

	std::vector<char>msgPayload = buildMessagePayload(
		destClientId.data(),
		TEXT_SEND_MSG_TYPE,
		cipher.length());



	do_connect();


	// send header, payload and content
	sendBytes(header, HEADER_SIZE);
	sendBytes(msgPayload, UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE);
	sendBytes(cipher, cipher.length());



	// receive response header + uuid
	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);
	recvBytes(UUID_SIZE);

	if (resHead->statusCode == SERVER_ERROR_CODE) {
		delete(resHead);
		throw std::exception("Server responded with an error");
	}
	std::cout << "Server status code: " << resHead->statusCode << std::endl;


	// receive destination client uuid + message id
	recvBytes(UUID_SIZE);
	recvBytes(MSG_ID_SIZE);
	std::cout << "Message ID: "; hexify((unsigned char*)data, MSG_ID_SIZE);
	delete(resHead);
}


/*
* Send ecrypted file to destination client
*/
void Client::handleSendFileMessage()
{
	if (!boost::filesystem::exists(ME_INFO))
		throw std::exception("Error, client not registered");


	// get destination client's uuid from its username
	std::string destUsername = getUserNameFromUser(MAX_ALLOWED_USERNAME);
	std::map<std::string, uuid>::iterator it = usernameToUuidMap.find(destUsername);
	if (it == usernameToUuidMap.end())
		throw std::exception("Username not found, aborting.");
	uuid destClientId = it->second;


	
	// check if key-exchage was performed with destination client
	symKey symmetricKey = { 0 };
	isValidKey(destClientId, &symmetricKey);



	// get file path
	std::string path = getInputFromUser("Enter full path of file ", MAX_MSG_LEN);


	// check if file exists
	if (!boost::filesystem::exists(path))
		throw std::exception("File not found");

	// check if file is not empty
	if (boost::filesystem::file_size(path) == 0)
		throw std::exception("Client's file size is 0");
	
	// check if file is too large
	if (boost::filesystem::file_size(path) >= pow(2, 32))
		throw std::exception("Client's file size is 0");
	
	uint32_t fileSize = boost::filesystem::file_size(path);



	// create encryption engine
	AESWrapper aes((unsigned char*)symmetricKey.data(), SYMMETRIC_KEY_SIZE);
	

	// calculate expected AES ciphertext length
	uint32_t cipherLen = 0;

	
	// for files smaller than CHUNK_SIZE - BLOCK_SIZE:
	if (fileSize < CHUNK_SIZE - BLOCKSIZE) {
		cipherLen = ((fileSize / BLOCKSIZE) + 1) * BLOCKSIZE;
	}
	
	// for bigger files, we need to take into account the fragmentation into chunks of the file:
	else{
		uint32_t numCipherChunks = fileSize / (CHUNK_SIZE - BLOCKSIZE);
		uint32_t remainderBytes = fileSize % (CHUNK_SIZE - BLOCKSIZE);

		uint32_t cipherChunk = (((CHUNK_SIZE - BLOCKSIZE) / BLOCKSIZE) + 1) * BLOCKSIZE;
		uint32_t cipherRemainder = (remainderBytes/BLOCKSIZE + 1) * BLOCKSIZE;
		
		cipherLen = cipherChunk * numCipherChunks + cipherRemainder;
	}


	// construct header and message payload	
	std::vector<char>header = buildHeader(
		clientID.data(),
		version,
		SEND_MESSAGE_CODE,
		UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE + cipherLen);

	std::vector<char>msgPayload = buildMessagePayload(
		destClientId.data(),
		FILE_SEND_MSG_TYPE,
		cipherLen);
	

	
	do_connect();


	// send header, payload and content
	sendBytes(header, HEADER_SIZE);
	sendBytes(msgPayload, UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE);
	sendFile(path, cipherLen, &aes);


	// receive response header + uuid
	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);
	recvBytes(UUID_SIZE);

	if (resHead->statusCode == SERVER_ERROR_CODE) {
		delete(resHead);
		throw std::exception("Server responded with an error");
	}
	std::cout << "Server status code: " << resHead->statusCode << std::endl;


	// receive destination client uuid + message id
	recvBytes(UUID_SIZE);
	recvBytes(MSG_ID_SIZE);
	std::cout << "Message ID: "; hexify((unsigned char*)data, MSG_ID_SIZE);
}


/*
* recevives the message content, and decryptes it with mutual symmetric key.
* and retures size of content bytes actually received + message header size.
*/
size_t Client::getTextMsg(Message* msg)
{
	uint32_t n = 0;
	uint32_t size = 0;
	uint32_t bytesCount = 0;
	std::string decrypted = "";
	uint32_t rounds = msg->contentSize / CHUNK_SIZE;


	std::cout << "From: ";
	std::map<uuid, std::string>::iterator it = uuidToUsernameMap.find(msg->clientID);
	if (it == uuidToUsernameMap.end())
		std::cout << "Unknow client" << std::endl;
	else
		std::cout << it->second << std::endl;

	
	symKey symmetricKey = { 0 };
	isValidKey(msg->clientID, &symmetricKey);
	AESWrapper aes((unsigned char*)symmetricKey.data(), SYMMETRIC_KEY_SIZE);
	


	std::cout << "Content:" << std::endl;
	while (n < rounds) {
		size = recvBytes(CHUNK_SIZE);
		decrypted = aes.decrypt(data, CHUNK_SIZE);
		std::cout << decrypted << std::endl;
		bytesCount += size;
		n++;
	}
	// receive the remaining bytes
	size = recvBytes(msg->contentSize - bytesCount);
	decrypted = aes.decrypt(data, size);
	std::cout << decrypted << std::endl;
	bytesCount += size;


	std::cout << "-----<EOM>-----\n" << std::endl;
	return UUID_SIZE + MSG_ID_SIZE + MSG_TYPE_SIZE + bytesCount;
}



/*
* recevives the file content and write to %TMP% with the name as the message id.
* retures size of content bytes actually received + message header size.
*/
size_t Client::getFileMsg(Message* msg)
{
	uint32_t n = 0;
	uint32_t size = 0;
	uint32_t bytesCount = 0;
	std::string decrypted = "";
	uint32_t rounds = msg->contentSize / CHUNK_SIZE;

	
	std::cout << "From: ";
	std::map<uuid, std::string>::iterator it = uuidToUsernameMap.find(msg->clientID);
	if (it == uuidToUsernameMap.end())
		std::cout << "Unknow client" << std::endl;
	else
		std::cout << it->second << std::endl;


	// check if file size is too large
	if (msg->contentSize > pow(2, 32))
		throw std::exception("File size too large, skipping message");

	
	std::string p = "";//  fix to TMP_PATH;
	p += std::to_string(msg->msgID);

	// print absolute path of file to be save in client's tmp memory dir
	std::cout << "Content:" << std::endl;
	std::cout << boost::filesystem::absolute(p);
	std::cout << std::endl;

	std::ofstream file;
	file.open(p, std::ios::out | std::ios::binary);
	if (!file)
		throw std::exception("File not open");



	symKey symmetricKey = { 0 };
	isValidKey(msg->clientID, &symmetricKey);
	AESWrapper aes((unsigned char*)symmetricKey.data(), SYMMETRIC_KEY_SIZE);



	
	while (n < rounds) {
		size = recvBytes(CHUNK_SIZE);
		decrypted = aes.decrypt(data, CHUNK_SIZE);
		file.write(decrypted.c_str(), decrypted.length());
		bytesCount += size;
		n++;
	}
	// receive the remaining bytes
	size = recvBytes(msg->contentSize - bytesCount);
	decrypted = aes.decrypt(data, size);
	file.write(decrypted.c_str(), decrypted.length());
	bytesCount += size;


	std::cout << "-----<EOM>-----\n" << std::endl;
	file.close();

	return UUID_SIZE + MSG_ID_SIZE + MSG_TYPE_SIZE + bytesCount;
}



/*
* A symmetric key is being sent to us by another client.(destination client).
* Message content of the client that has sent us this message, (destination client),
* contains his symmetric key - encrypted with our public key.
* This is a part of the key exchange protocol.
*
* To extract the symmetric key we need to do the following:
*  - get our public key from memory.
*  - take the encrypted symmetric key from the message.
*  - decrypt the message content with our ** private ** key.
*  - the decrypted bytes are the symmetric key that the destination client
*    has sent us.
*  - now both we and the destination client posses the same symmetric key,
*    and we can now send encrypted texts and files to each other.
*/
size_t Client::getSymmetricKey(Message* msg)
{
	uint32_t size = 0;
	std::string decrypted = "";
	symKey symmetricKey = { 0 };


	size = recvBytes(msg->contentSize);
	
	decrypted = rsapriv->decrypt(data, size);

	memcpy(symmetricKey.data(), decrypted.c_str(), decrypted.length());
	destCidToSymKeyMap.insert({ msg->clientID, symmetricKey });


	std::cout << "From: ";
	std::map<uuid, std::string>::iterator it = uuidToUsernameMap.find(msg->clientID);
	if (it == uuidToUsernameMap.end())
		std::cout << "Unknow client" << std::endl;
	else
		std::cout << it->second << std::endl;
	std::cout << "Content:" << std::endl;
	std::cout << "Symmetric key received" << std::endl;
	std::cout << "-----<EOM>-----\n" << std::endl;

	return UUID_SIZE + MSG_ID_SIZE + MSG_TYPE_SIZE + size;
}


/*
* A symmetric key request by another client. This message type has no payload
* according to protocol.
* There is nothing here to be done.
*/
size_t Client::getRequestForSymmetricKey(Message* msg)
{
	std::cout << "From: ";
	std::map<uuid, std::string>::iterator it = uuidToUsernameMap.find(msg->clientID);
	if (it == uuidToUsernameMap.end())
		std::cout << "Unknow client" << std::endl;
	else
		std::cout << it->second << std::endl;
	std::cout << "Content:" << std::endl;
	std::cout << "Request for symmetric key" << std::endl;
	std::cout << "-----<EOM>-----\n" << std::endl;

	return UUID_SIZE + MSG_ID_SIZE + MSG_TYPE_SIZE + 0;
}



/*
* Create a symmetric key to communicate with destination client.
*/
symKey Client::createSymmetricKey()
{
	symKey key = { 0 };
	AESWrapper::GenerateKey((unsigned char*)key.data(), SYMMETRIC_KEY_SIZE);

	//std::cout << "Created Symmetric key" << std::endl;
	//hexify((unsigned char*)key.data(), SYMMETRIC_KEY_SIZE);
	return key;
}


/*
* Create a symmetric key, encrypt it with destination client's ** public key ** and send it
* to destination client as a message.
*/
void Client::handleSendMySymmetricKey()
{
	if (!boost::filesystem::exists(ME_INFO))
		throw std::exception("Error, client not registered");


	// get destination client's uuid from its username
	std::string destUsername = getUserNameFromUser(MAX_ALLOWED_USERNAME);
	std::map<std::string, uuid>::iterator it = usernameToUuidMap.find(destUsername);
	if (it == usernameToUuidMap.end())
		throw std::exception("Username not found, aborting.");

	uuid destClientId = it->second;


	// check if we have the public key of the destination client
	// otherwise we cannot send the symmetric key
	std::map<uuid, pubKey>::iterator iter;
	iter = destCidToPubKeyMap.find(destClientId);
	if (iter == destCidToPubKeyMap.end())
		throw std::exception("Destination client's public key not found, aborting.");

	pubKey destPubKey = iter->second;


	// create symmetric key for destination client
	symKey symmetricKey = createSymmetricKey();

	// add pair to map
	destCidToSymKeyMap.insert({ destClientId, symmetricKey });


	// temporarly create RSA encryptor 
	// and encrypt the symmetric key with destination client's public key
	RSAPublicWrapper rsapub(destPubKey.data(), PUB_KEY_SIZE);
	std::string cipher = rsapub.encrypt(symmetricKey.data(), symmetricKey.size());


	// construct header and message payload	
	std::vector<char>header = buildHeader(
		clientID.data(),
		version,
		SEND_MESSAGE_CODE,
		UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE + cipher.size());

	std::vector<char>msgPayload = buildMessagePayload(
		destClientId.data(),
		SYMMETRIC_KEY_SEND_MSG_TYPE,
		cipher.size());


	do_connect();

	// send header, payload and content
	sendBytes(header, HEADER_SIZE);
	sendBytes(msgPayload, UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE);
	sendBytes(cipher, cipher.size());


	// receive response header + uuid
	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);
	recvBytes(UUID_SIZE);

	if (resHead->statusCode == SERVER_ERROR_CODE) {
		delete(resHead);
		throw std::exception("Server responded with an error");
	}
	std::cout << "Server status code: " << resHead->statusCode << std::endl;


	// receive destination client uuid + message id
	recvBytes(UUID_SIZE);
	recvBytes(MSG_ID_SIZE);
	std::cout << "Message ID: "; hexify((unsigned char*)data, MSG_ID_SIZE);

}



/* 
* check if key-exchage was performed with destination client.
* if symmetric key exists in memory then assign it. otherwise
* throw an error and exit.
*/
void Client::isValidKey(uuid id, symKey * symmetricKey)
{
	std::map<uuid, symKey>::iterator iter = destCidToSymKeyMap.find(id);
	if (iter == destCidToSymKeyMap.end())
		throw std::exception("Symmetric key was not found for destination client.");

	memcpy(symmetricKey->data(), iter->second.data(), SYMMETRIC_KEY_SIZE);
}




/*
* Send a request for symmetric key from destination client.
* The request is in a form of a message.
* Message content is empty, only the header exists.
* Hence, no encryption needed here with a public key.
*/
void Client::handleRequestForSymmetricKey()
{
	if (!boost::filesystem::exists(ME_INFO))
		throw std::exception("Error, client not registered");



	// get destination client's uuid from its username
	std::string destUsername = getUserNameFromUser(MAX_ALLOWED_USERNAME);
	std::map<std::string, uuid>::iterator it = usernameToUuidMap.find(destUsername);
	if (it == usernameToUuidMap.end())
		throw std::exception("Username not found, aborting.");
	
	uuid destClientId = it->second;


	// check if we have the public key of the destination client
	std::map<uuid, pubKey>::iterator iter;
	iter = destCidToPubKeyMap.find(destClientId);
	if (iter == destCidToPubKeyMap.end())
		throw std::exception("Destination client's public key not found, aborting.");


	// construct header and message payload	
	std::vector<char>header = buildHeader(
		clientID.data(),
		version,
		SEND_MESSAGE_CODE,
		UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE + 0);

	std::vector<char>msgPayload = buildMessagePayload(
		destClientId.data(),
		SYMMETRIC_KEY_REQUEST_MSG_TYPE,
		0);


	do_connect();

	// send header, payload (content is empty in this case)
	sendBytes(header, HEADER_SIZE);
	sendBytes(msgPayload, UUID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE);


	// receive response header + uuid
	recvBytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parseResponseHeader(resHead, data);
	recvBytes(UUID_SIZE);

	if (resHead->statusCode == SERVER_ERROR_CODE) {
		delete(resHead);
		throw std::exception("Server responded with an error");
	}
	std::cout << "Server status code: " << resHead->statusCode << std::endl;


	// receive destination client uuid + message id
	recvBytes(UUID_SIZE);
	std::cout << "Sent message to client" << std::endl;  //hexify((unsigned char*)data, UUID_SIZE);
	recvBytes(MSG_ID_SIZE);
	std::cout << "Message ID: "; hexify((unsigned char*)data, MSG_ID_SIZE);
}


/*
* Receive bytes of the message header and save the unpacked header
* parameters to their appropriate fields in Message structure
*/
void Client::recvAndParseMessageHeader(Message* msg)
{
	/* message source (client id) */
	recvBytes(UUID_SIZE);
	memcpy(msg->clientID.data(), data, UUID_SIZE);

	/* unique message id */
	recvBytes(MSG_ID_SIZE);
	msg->msgID = (uint8_t)(data[3]) << 24 |
		(uint8_t)(data[2]) << 16 |
		(uint8_t)(data[1]) << 8 |
		(uint8_t)(data[0]);


	/* message type uint8_t */
	recvBytes(MSG_TYPE_SIZE);
	msg->msgType = data[0];

	/* read content size uint32_t */
	recvBytes(CONTENT_SIZE);
	msg->contentSize = (uint8_t)(data[3]) << 24 |
		(uint8_t)(data[2]) << 16 |
		(uint8_t)(data[1]) << 8 |
		(uint8_t)(data[0]);
}


/*
* Parse the me.info file's fileds into client's memory
*/
void Client::parseInfoFile(const std::string filename)
{
	std::string line = "";
	std::ifstream f = openInFile(filename);

	try
	{
		// client username
		std::getline(f, line);
		if (line.size() == 0 && line.size() > MAX_ALLOWED_USERNAME)
			throw std::exception();
		username = line;


		// cpoy client id
		std::getline(f, line);
		if (line.size() == 0 && line.size() > (UUID_SIZE * 2))
			throw std::exception();

		// convert from hex string to bytes
		ascii2HexBytes(clientID.data(), line, UUID_SIZE);


		// copy private key base64 encoded
		while (std::getline(f, line))
			base64Pivatekey += line;  // does not include whitespace character
	}
	catch (const std::exception&)
	{
		f.close();
		throw std::exception("Error reading client's info file");
	}
	f.close();
}


/*
* Get bytes of the response header from server and save the unpacked header
* parameters to their appropriate fields in ResponseHeader structure
*/
void Client::parseResponseHeader(ResponseHeader* rh, char* arr)
{
	rh->serverVersion = (uint8_t)arr[0];

	rh->statusCode = (uint8_t)arr[2] << 8 | (uint8_t)arr[1];

	rh->payloadSize = (uint8_t)(arr[6]) << 24 |
		(uint8_t)(arr[5]) << 16 |
		(uint8_t)(arr[4]) << 8 |
		(uint8_t)(arr[3]);
}


/*
* opens a file for output
*/
std::ofstream Client::openOutFile(const std::string filename)
{
	std::ofstream file;
	file.open(filename);
	if (!file)
		throw std::exception("File not open");
	return file;
}


/*
* opens a file for input
*/
std::ifstream Client::openInFile(const std::string filename)
{
	std::ifstream file;
	file.open(filename);
	if (!file)
		throw std::exception("File not open");
	return file;
}


std::string Client::hex2Ascii(const char* arr, size_t len)
{
	std::stringstream converter;
	converter << std::hex << std::setfill('0');

	for (size_t i = 0; i < len; i++)
		converter << std::setw(2) << (static_cast<unsigned>(arr[i]) & 0xFF);
	return converter.str();
}


void Client::ascii2HexBytes(char* dest, const std::string src, size_t len)
{
	std::string bytes = "";
	std::stringstream converter;
	converter << std::hex << std::setfill('0');

	for (size_t i = 0; i < (len * 2); i += 2)
	{
		converter << std::hex << src.substr(i, 2);
		int byte;
		converter >> byte;
		bytes += (byte & 0xFF);
		converter.str(std::string());
		converter.clear();
	}
	memcpy(dest, bytes.c_str(), len);
}


std::string Client::getUserNameFromUser(uint16_t maxChars)
{
	std::string name(maxChars, '\0');
	std::cout << "Insert a user name, max allowed chars (including NULL) is " << maxChars << std::endl;
	std::cout << "> ";
	std::getline(std::cin, name);

	// only support printable characters
	for (uint32_t i = 0; i < name.length(); i++) {
		if (!std::isprint(name[i]))
			throw std::exception("User input is not printable");
	}

	// make sure to set the last character to '\0'
	if ((name.back() != '\0') && (name.length() == maxChars))
		name.back() = '\0';
	return name;
}


std::string Client::getInputFromUser(const char* instructions, const uint32_t maxChars)
{
	std::string content(maxChars, '\0');
	std::cout << instructions << std::endl;
	std::cout << "> ";
	std::getline(std::cin, content);

	// only support printable characters
	for (uint32_t i = 0; i < content.length(); i++) {
		if (!std::isprint(content[i]))
			throw std::exception("User input is not printable");
	}
	return content;
}


std::string Client::getClientIDFromUser()
{
	std::stringstream stripped;
	std::string clientId(47, 0);
	std::cout << "Insert a client ID, hex ASCII chars with space in between" << std::endl;
	std::cout << "Example: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff  (47 chars in total)" << std::endl;
	std::cout << "> ";

	std::getline(std::cin, clientId);
	if (clientId.size() != 47)
		throw std::exception("Invalid UUID format input from user.");

	// strip the string from its whitespaces
	for (auto c : clientId) {
		if (c != ' ')
			stripped << c;
	}
	return stripped.str();
}


/*
* Returns a client header vector according to the given parameters
* and according to protocol.
* 	   clientId   16 byte
*	   version    1 bytes
*	   op code    2 bytes
*	   size       4 bytes
*/
std::vector<char> Client::buildHeader(char* clientId, char version, uint16_t code, uint32_t size)
{
	std::vector<char> header;

	for (size_t i = 0; i < UUID_SIZE; i++)
		header.push_back((uint8_t)clientId[i]);

	header.push_back(version);

	header.push_back((uint8_t)(code));
	header.push_back((uint8_t)(code >> 8));

	header.push_back((uint8_t)(size));
	header.push_back((uint8_t)(size >> 8));
	header.push_back((uint8_t)(size >> 16));
	header.push_back((uint8_t)(size >> 24));

	return header;
}


/*
* Returns a message payload vector according to the given parameters
* and according to protocol.
* Notice that we do not refer to the actual content.
* The content will be sent afterwards.
*
*   destclientID    uuid 16 bytes
	msgType			message type 1 byte
	size			size of message content 4 byte
*/
std::vector<char> Client::buildMessagePayload(char* destClientID, uint8_t msgType, uint32_t size)
{
	std::vector<char> msgPayload;

	for (size_t i = 0; i < UUID_SIZE; i++)
		msgPayload.push_back((uint8_t)destClientID[i]);

	msgPayload.push_back((uint8_t)msgType);

	msgPayload.push_back((uint8_t)(size));
	msgPayload.push_back((uint8_t)(size >> 8));
	msgPayload.push_back((uint8_t)(size >> 16));
	msgPayload.push_back((uint8_t)(size >> 24));

	return msgPayload;
}



/*
* Attempt to receive an exact amount
*/
size_t Client::recvBytes(size_t amount)
{
	clearBuffer(data, CHUNK_SIZE);
	size_t bytesRecv = boost::asio::read(socket_, boost::asio::buffer(data, amount));

	if (bytesRecv < amount) {
		clearBuffer(data, CHUNK_SIZE);
		std::string err = "Received fewer bytes than expected " + std::to_string(bytesRecv) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesRecv;
}



/*
* Open a file from specified path, and send its content in chunks, till the end of file 
* where the chunks are encrypted with our shared symmetric key with the destination client.
*/
void Client::sendFile(std::string filepath, uint32_t cipherLen, AESWrapper * aes)
{
	std::string cipher = "";
	uint32_t bytesCount = 0;
	std::ifstream file(filepath, std::ios::binary);
	clearBuffer(data, CHUNK_SIZE);


	std::cout << "Expecting to send: " << cipherLen << " bytes" << std::endl;
	std::cout << "Uploading..." << std::endl;


	while (!file.eof())
	{
		file.read(data, CHUNK_SIZE - BLOCKSIZE);
		cipher = aes->encrypt(data, (unsigned int)file.gcount());
		
		// cipher length should less or equal to CHUNK_SIZE
		bytesCount += sendBytes(cipher, cipher.length());
	}
	

	std::cout << "Actually sent    : " << bytesCount << " bytes" << std::endl;
	file.close();
}



size_t Client::sendBytes(char* data, size_t amount)
{
	size_t bytesSent = boost::asio::write(socket_, boost::asio::buffer(data, amount));

	if (bytesSent < amount) {
		std::string err = "Sent fewer bytes than expected " + std::to_string(bytesSent) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesSent;
}



size_t Client::sendBytes(std::vector<char> vec, size_t amount)
{
	size_t bytesSent = boost::asio::write(socket_, boost::asio::buffer(vec, amount));

	if (bytesSent < amount) {
		std::string err = "Sent fewer bytes than expected " + std::to_string(bytesSent) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesSent;
}



size_t Client::sendBytes(std::string str, size_t amount)
{
	size_t bytesSent = boost::asio::write(socket_, boost::asio::buffer(str, amount));

	if (bytesSent < amount) {
		std::string err = "Sent fewer bytes than expected " + std::to_string(bytesSent) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesSent;
}


/*
* Read the server's ip and port from the file "server.info" located inside the exe dir.
* The format is- ip:port.
* Check whether the read ip and port are compatible with the TCP/IP standard
* and return the appropriate status code.
*/
void Client::getServerInfo()
{
	std::string line = "";
	std::string port = "";
	std::string ip = "";
	size_t pos;


	if (!boost::filesystem::exists(SERVER_INFO))
		throw std::exception("server.info file does not exist");

	// get the ip and port
	// attempt to open the file and read the line
	std::ifstream file;

	file = openInFile(SERVER_INFO);
	std::getline(file, line);

	if (line.size() == 0) {
		file.close();
		throw std::exception("getServerInfo, File is empty");
	}


	std::cout << "Server info " << line << std::endl;

	// take out the ip and port substrings
	pos = line.find(":");
	if (pos != std::string::npos)
	{
		ip = line.substr(0, pos);
		port = line.substr(pos + 1);
	}

	// check whether the ip and port are valid
	if (port.size() > 0 && port.size() <= 4)
	{
		port_ = std::stoi(port);  // assign to class member
	}
	else
	{
		file.close();
		throw std::exception("Invalid port number");
	}

	boost::asio::ip::address ip_add = boost::asio::ip::make_address(ip);
	if (!ip_add.is_v4())
	{
		file.close();
		throw std::exception("Invalid ip v4 address");
	}

	ip_ = ip_add; // assign to class member
}


/*
* closes socket connection to server
*/
void Client::close()
{
	socket_.close();
}


void Client::clearBuffer(char* buf, uint32_t size)
{
	for (uint32_t i = 0; i < size; i++)
		buf[i] = 0;
}


void Client::printBuffer(char* buf, uint32_t length)
{
	for (uint32_t i = 0; i < length; i++)
		printf("%02x:", (uint8_t)buf[i]);
	std::cout << std::endl;
	std::cout << std::endl;
}


void Client::printChars(char* buf, uint32_t start, uint32_t length, bool endLine)
{
	for (uint32_t i = start; i < length; i++) {
		if (buf[i])
			std::cout << buf[i];
		else
			break;
	}
	if (endLine)
		std::cout << std::endl;
}


void Client::hexify(const unsigned char* buffer, unsigned int length)
{
	std::ios::fmtflags f(std::cout.flags());
	std::cout << std::hex;
	for (size_t i = 0; i < length; i++)
		std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
	std::cout << std::endl;
	std::cout.flags(f);
}



void Client::run()
{
	int reqOp = 0;


	while (true)
	{
		std::cout << "\n\nMessageU client at your service.\n\n" <<
			"10) Register\n" <<
			"20) Request for clients list\n" <<
			"30) Request for public key\n" <<
			"40) Request for waiting messages\n" <<
			"50) Send a text message\n" <<
			"51) Send a request for symmetric key\n" <<
			"52) Send your symmetric key\n" <<
			"53) Send a file\n" <<
			" 0) Exit client\n" <<
			"?" <<
			std::endl;

		if (!(std::cin >> reqOp)) {
			std::cout << "Please enter valid numbers only." << std::endl;
			std::cin.clear();
			std::cin.ignore(INT_MAX, '\n');
			continue;
		}
		std::cin.clear();
		std::cin.ignore(INT_MAX, '\n');

		try
		{

			switch (reqOp)
			{
			case REGISTER_REQUEST:
				handleRegistration();
				break;

			case CLIENTS_LIST_REQUEST:
				handleClientsList();
				break;

			case PUBLIC_KEY_REQUEST:
				handlePublicKeyRequest();
				break;

			case WAITING_MESSAGES_REQUEST:
				handlRequestForWaitingMessages();
				break;

			case SEND_MESSAGE:
				handleSendTextMessage();
				break;


			case SEND_REQUEST_FOR_SYMMETRIC_KEY:
				handleRequestForSymmetricKey();
				break;


			case SEND_MY_SYMMETRIC_KEY:
				handleSendMySymmetricKey();
				break;


			case SEND_FILE:
				handleSendFileMessage();
				break;

			case EXIT:
				return;

			default:
				break;
			}


			close();
		}
		catch (std::exception& e)
		{
			close();
			std::cerr << "Exception: " << e.what() << "\n";
		}
	}
}






