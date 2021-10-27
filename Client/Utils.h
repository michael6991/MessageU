#pragma once
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include <iostream>
#include <array>


/* constants in bytes */
#define CHUNK_SIZE  (1024)
#define HEADER_SIZE (23)
#define HEADER_SIZE_RESPONSE (7)
#define MAX_MSG_LEN (65536)
#define USER_OP_LEN (2)
#define MAX_ALLOWED_USERNAME (255)
#define MSG_TYPE_SIZE (1)
#define MSG_ID_SIZE (4)
#define CONTENT_SIZE (4)
#define UUID_SIZE (16)
#define BLOCKSIZE (16)  // AES block size
#define PUB_KEY_SIZE (RSAPublicWrapper::KEYSIZE)		 // RSA 1024 bit X509 format
#define SYMMETRIC_KEY_SIZE (AESWrapper::DEFAULT_KEYLENGTH)  // AES-CBC 128 bit
#define SERVER_INFO ("server.info")
#define ME_INFO     ("me.info")


/* Socket timeout on receive and send operations (ms) */
#define RCV_TIMEOUT (15000)
#define SND_TIMEOUT (15000)


/* Operation constants defenition */
#define REGISTER_REQUEST (10)
#define REGISTER_CODE (1000)
#define REGISTER_SUCCESS_STATUS (2000)

#define CLIENTS_LIST_REQUEST (20)
#define CLIENTS_LIST_CODE (1001)
#define CLIENTS_LIST_SUCCESS_STATUS (2001)


#define PUBLIC_KEY_REQUEST (30)
#define PUBLIC_KEY_CODE (1002)
#define PUBLIC_KEY_SUCCESS_STATUS (2002)


#define SEND_MESSAGE (50)
#define SEND_MESSAGE_CODE (1003)
#define SEND_MESSAGE_SUCCESS_STATUS (2003)


#define SEND_REQUEST_FOR_SYMMETRIC_KEY (51)
#define SEND_MY_SYMMETRIC_KEY (52)
#define SEND_FILE (53)



#define WAITING_MESSAGES_REQUEST (40)
#define WAITING_MESSAGES_CODE (1004)
#define WAITING_MESSAGES_SUCCESS_STATUS (2004)


#define SERVER_ERROR_CODE (9000)


#define EXIT (0)


/* message types */
#define SYMMETRIC_KEY_REQUEST_MSG_TYPE (1)
#define SYMMETRIC_KEY_SEND_MSG_TYPE (2)
#define TEXT_SEND_MSG_TYPE (3)
#define FILE_SEND_MSG_TYPE (4)


typedef std::array<char, UUID_SIZE> uuid;





struct FullRequestHeader {
	uuid clientID = { 0 };					// uuid 16 bytes
	uint8_t version = 0;					// version 1 byte
	uint16_t code = 0;						// request code 2 bytes
	uint32_t payloadSize = 0;				// size of payload to send
};


struct ResponseHeader {
	uint8_t serverVersion = 0;
	uint16_t statusCode = 0;
	uint32_t payloadSize = 0;
};


struct Message {
	uuid clientID = { 0 };					// source/dest client uuid 16 bytes
	uint32_t msgID = 0;						// message id 4 bytes
	uint8_t msgType = 0;					// message type 1 byte
	uint32_t contentSize = 0;				// size of message content 4 byte
};


