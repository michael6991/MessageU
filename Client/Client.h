#pragma once

#include "Utils.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"

#include <cstdlib>
#include <array>
#include <deque>
#include <map>
#include <vector>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>



using boost::asio::ip::tcp;


typedef std::array<char, UUID_SIZE> uuid;
typedef std::array<char, PUB_KEY_SIZE> pubKey;
typedef std::array<char, SYMMETRIC_KEY_SIZE> symKey;


typedef boost::asio::detail::socket_option::integer<SOL_SOCKET, SO_RCVTIMEO> rcv_timeout_option;
typedef boost::asio::detail::socket_option::integer<SOL_SOCKET, SO_SNDTIMEO> snd_timeout_option;




class Client
{


private:

    void do_connect();
    void handleRegistration();
    void handleClientsList();
    void handlePublicKeyRequest();
    void handlRequestForWaitingMessages();
    void handleSendTextMessage();
    void handleSendFileMessage();
    void handleSendMySymmetricKey();
    void handleRequestForSymmetricKey();


    symKey createSymmetricKey();   
    size_t getSymmetricKey(Message* msg);
    size_t getRequestForSymmetricKey(Message* msg);


    std::string getUserNameFromUser(const uint16_t maxChars);
    std::string getClientIDFromUser();
    std::string getInputFromUser(const char * instructions, const uint32_t maxChars);
    std::string hex2Ascii(const char* arr, size_t len);
    
    
    void getServerInfo();
    void configureTimeouts();
    void recvAndParseMessageHeader(Message* msg);
    void clearBuffer(char * buf, uint32_t size);
    void printBuffer(char* buf, uint32_t length);
    void printChars(char* buf, uint32_t start, uint32_t length, bool endLine=true);
    void parseResponseHeader(ResponseHeader* rh, char* arr);
    void parseInfoFile(const std::string filename);
    void ascii2HexBytes(char* dest, const std::string src, size_t len);
    void hexify(const unsigned char* buffer, unsigned int length);
    void sendFile(std::string filepath, uint32_t cipherLen, AESWrapper* aes);
    void isValidKey(uuid id, symKey * symmetricKey);
    

    size_t sendBytes(char * data, size_t amount);
    size_t sendBytes(std::vector<char> vec, size_t amount);
    size_t sendBytes(std::string str, size_t amount);
    size_t recvBytes(size_t amount);
    size_t getTextMsg(Message* msg);
    size_t getFileMsg(Message* msg);
    

    std::ofstream openOutFile(const std::string filename);
    std::ifstream openInFile(const std::string filename);
    std::vector<char> buildHeader(char * clientId, char version, uint16_t code, uint32_t size);
    std::vector<char> buildMessagePayload(char* destClientID, uint8_t msgType, uint32_t size);
    
    
    
    /*  tcp ip  */
    boost::asio::ip::address ip_;
    uint16_t port_;

    /*  user information and keys */
    std::string username = "";
    std::string privateKey = "";
    std::string base64Pivatekey = "";
    pubKey publicKey = { 0 };
    uuid clientID = { 0 };
    
    

    /*  session variables   */
    char data[CHUNK_SIZE] = { 0 };
    uint16_t status = 0;
    

    
    /*  session objects     */
    boost::asio::io_context& io_context_;
    tcp::socket socket_;
    RSAPrivateWrapper * rsapriv = nullptr; // RSA private/public key pair engine and decryptor
    RSAPublicWrapper * rsapub = nullptr;   // RSA encryptor with public key
        
    
    /* destination client id and its associated public key (from char array to char array) */
    std::map<uuid, pubKey> destCidToPubKeyMap;

    /* destination client id and its associated symmetric key (from char array to char array) */
    std::map<uuid, symKey> destCidToSymKeyMap;

    /* map username to client id */
    std::map<std::string, uuid> usernameToUuidMap;

    /* map client id to username */
    std::map<uuid, std::string> uuidToUsernameMap;




public:

    Client() = default;
    Client(boost::asio::io_context& io_context);
    ~Client();

    void run();
    void close();    
    char version = 2;
};



