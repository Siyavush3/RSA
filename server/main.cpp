#include "../tcp/hdr/TcpServer.h"
#include "../tcp/hdr/TcpClient.h"
#include <iostream>
#include <stdlib.h>
#include <mutex>
#include <map>
#include <fstream>
#include <cryptopp/hex.h>
#include <iostream>
using std::cout;
using std::endl;
#include <iomanip>
using std::hex;
#include <string>
using std::string;
#include "cryptopp/rsa.h"
using CryptoPP::RSA;
#include "cryptopp/integer.h"
using CryptoPP::Integer;
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
#include <cryptopp/files.h>
AutoSeededRandomPool rnd;


const std::string CRYPT = "CRYPT::";
const std::string ENCMY = "ENC::";
const std::string ENCOther = "ENC_FROM_ID::";
const std::string  VALID= "VALID::";
const std::string  CREATE= "CREATE::";

struct Keys
{
    RSA::PrivateKey PrivK;
    RSA::PublicKey PubK;
};

void Encode(const string& filename, const CryptoPP::BufferedTransformation& bt)
{
    CryptoPP::FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}


void Decode(const string& filename, CryptoPP::BufferedTransformation& bt)
{
    CryptoPP::FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

void EncodePrivateKey(const string& filename, const RSA::PrivateKey& key)
{
    CryptoPP::ByteQueue queue;
    key.DEREncodePrivateKey(queue);

    Encode(filename, queue);
}

void EncodePublicKey(const string& filename, const RSA::PublicKey& key)
{
    CryptoPP::ByteQueue queue;
    key.DEREncodePublicKey(queue);

    Encode(filename, queue);
}


void DecodePrivateKey(const string& filename, RSA::PrivateKey& key)
{
    CryptoPP::ByteQueue queue;

    Decode(filename, queue);
    key.BERDecodePrivateKey(queue, false /*paramsPresent*/, queue.MaxRetrievable());
}

void DecodePublicKey(const string& filename, RSA::PublicKey& key)
{
    CryptoPP::ByteQueue queue;

    Decode(filename, queue);
    key.BERDecodePublicKey(queue, false /*paramsPresent*/, queue.MaxRetrievable());
}



std::string SHA256(std::string message ){
    CryptoPP::SHA256 hash;
    byte digest[ CryptoPP::SHA256::DIGESTSIZE ];


    hash.CalculateDigest( digest, (byte*) message.c_str(), message.length() );

    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();    
    return output;
}


class Database 
{
    public:
        bool AddClient(std::string Addlogin,std::string pass) 
        {
            if(storage.count(Addlogin)>0 )
            {
                return false;
            }
            else{
                storage.insert(make_pair(Addlogin,SHA256(pass)));
                RSA::PrivateKey privKey = CreateKeys().PrivK;
                std::string filename =  Addlogin + "-priv"+".key";
                EncodePrivateKey(filename,privKey);
                
                RSA::PublicKey pubKey = CreateKeys().PubK;
                std::string privfilename = Addlogin + "-pub"+".key";
                EncodePublicKey(privfilename,pubKey);
                return true;
            }
            
        }

        RSA::PublicKey FindPub(std::string FLogin) const {
            RSA::PublicKey pbK;
            std::string filename = FLogin + "-pub"+".key";
            DecodePublicKey(filename,pbK);
            return pbK;
        }
        RSA::PrivateKey FindPriv(std::string Login) const {
            RSA::PrivateKey prvK;
            std::string filename = Login + "-priv"+".key";
            DecodePrivateKey(filename,prvK);
            return prvK;
        }
        bool Valid(std::string VLogin,std::string Pass)
        {
            if(storage.find(VLogin)->second == SHA256(Pass))
            {
                return true;            
            }
            else
            {
                return false;
            }
        }
        void LoadDB()
        {
            std::map<string, string> myMap;
            string key;
            string value;
            std::ifstream in("DataBase.dat");
            if (in.is_open())
            {
                while (in >> key >> value){
                    myMap.insert(make_pair(key,value)) ;
                }
            }
            in.close();
            storage.clear();
            storage = myMap;
        }
        void SaveDB()
        {
            std::fstream file;
            file.open("DataBase.dat", std::fstream::out);
  
            for (auto it = storage.begin(); it != storage.end(); ++it) 
            {
              file<<it->first<<"\t"<<it->second<<"\n";
            }
 
             file.close();
        }
    private:
    Keys CreateKeys()
    {

        RSA::PrivateKey rsaPrivate;
        rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);

        RSA::PublicKey rsaPublic(rsaPrivate);
        Keys out;
        out.PubK = rsaPublic;
        out.PrivK = rsaPrivate;
        return out;

    }
    std::map<std::string, std::string> storage;
};



bool isCRYPTCommand(std::string_view message) {
    return message.find(CRYPT) == 0;
}
bool isEncryptMyCommand(std::string_view message) {
    return message.find(ENCMY) == 0;
}
bool isEncryptOtherCommand(std::string_view message) {
    return message.find(ENCOther) == 0;
}
bool isValidCommand(std::string_view message) {
    return message.find(VALID) == 0;
}
bool isCreateCommand(std::string_view message) {
    return message.find(CREATE) == 0;
}
AutoSeededRandomPool prng;

std::string Crypt(std::string cryptlogin,std::string msg)
{
    
    
    Database db;
    db.LoadDB();
    std::stringstream ss;
    std::string result;
    Integer m, c;
    RSA::PublicKey pubKey = db.FindPub(cryptlogin);
    
    
	m = Integer((const byte *)msg.data(), msg.size());
	

	// Encrypt
	c = pubKey.ApplyFunction(m);
	ss << hex << c << endl;
    ss>>result;
    
    return result ;
}
std::string Enc(std::string enclogin,std::string Encmsg)
{

    Database Encdb;
    Encdb.LoadDB();
    std::stringstream ss;
    RSA::PrivateKey privKey = Encdb.FindPriv(enclogin);
    string recovered;
    Integer  r,p;
    ss << Encmsg;
    ss>>p;
	r = privKey.CalculateInverse(prng, p);
	// Round trip the message
	size_t req = r.MinEncodedSize();
	recovered.resize(req);
	r.Encode((byte *)recovered.data(), recovered.size());
    return recovered;
}


std::string parseEncOtherLogin(std::string_view message) {
    std::string_view rest = message.substr(ENCOther.length());
    int pos = rest.find("::");
    std::string_view id = rest.substr(0, pos);
    return std::string(id);
}

std::string parseValidPass(std::string_view message) {
    std::string_view rest = message.substr(VALID.length());
    int pos = rest.find("::");
    std::string_view text = rest.substr(pos+2);
    return std::string(text);
}
std::string parseValidLogin(std::string_view message) {
    std::string_view rest = message.substr(VALID.length());
    int pos = rest.find("::");
    std::string_view id = rest.substr(0, pos);
    return std::string(id);
}
std::string parseCreatePass(std::string_view message) {
    std::string_view rest = message.substr(VALID.length());
    int pos = rest.find("::");
    std::string_view text = rest.substr(pos+2);
    return std::string(text);
}
std::string parseCreateLogin(std::string_view message) {
    std::string_view rest = message.substr(VALID.length());
    int pos = rest.find("::");
    std::string_view id = rest.substr(0, pos);
    return std::string(id);
}

std::string parseEncOtherMessage(std::string_view message) {
    std::string_view rest = message.substr(ENCOther.length());
    int pos = rest.find("::");
    std::string_view text = rest.substr(pos+2);
    return std::string(text);
}
std::string parseEncMyMsg(std::string_view message) {
    std::string_view rest = message.substr(ENCMY.length());
    int pos = rest.find("::");
    std::string_view id = rest.substr(0, pos);
    return std::string(id);
}



std::string parseCryptMsg(std::string_view message) {
    std::string_view rest = message.substr(CRYPT.length());
    int pos = rest.find("::");
    std::string_view id = rest.substr(0, pos);
    return std::string(id);
}


std::string getHostStr(const TcpServer::Client& client) {
    uint32_t ip = client.getHost ();
    return std::string() + std::to_string(int(reinterpret_cast<char*>(&ip)[0])) + '.' +
            std::to_string(int(reinterpret_cast<char*>(&ip)[1])) + '.' +
            std::to_string(int(reinterpret_cast<char*>(&ip)[2])) + '.' +
            std::to_string(int(reinterpret_cast<char*>(&ip)[3])) + ':' +
            std::to_string( client.getPort ());
}


TcpServer server( 8080,

[](DataBuffer data, TcpServer::Client& client){
   
    Database db;
    db.LoadDB();
    static std::string ThisUserLogin;
    std::string RecvCommand;
    std::string SendCommand;
    bool Valid = false;
    char bf[1024];
    std::strcpy(bf,(char *)data.data_ptr);
    RecvCommand = std::string(bf);
    if(isValidCommand(RecvCommand))
    {
        std::string VerfLog,VerfPass;
        VerfLog =parseValidLogin(RecvCommand);
        VerfPass = parseValidPass(RecvCommand);
        Valid =  db.Valid(":"+VerfLog,VerfPass);
        if(Valid)
        {
            SendCommand = VALID +"VALIDATED";
            ThisUserLogin = VerfLog;
        }
        if(!Valid)
        {
            SendCommand = VALID+"WRONG_LOGIN_OR_PASSWORD";
        }

    }
    if(isCreateCommand(RecvCommand))
    {   
        std::string Createlogin,CraetePass;
        bool isCanCreate = false;
        Createlogin =parseCreateLogin(RecvCommand);
        CraetePass = parseCreatePass(RecvCommand);
        isCanCreate = db.AddClient(Createlogin, CraetePass);
        
        if(isCanCreate)
        {
            SendCommand = CREATE+"User_created";
            ThisUserLogin =Createlogin;
        }
        else
        {
            SendCommand = CREATE+"Login_busy";
        }

    }
    if(isCRYPTCommand(RecvCommand))
    {    
        std::string CryptMsg;
        CryptMsg = parseCryptMsg(RecvCommand);
        std::string Crypted = Crypt(ThisUserLogin,CryptMsg);
        SendCommand = CRYPT+Crypted;
    }
    if(isEncryptMyCommand(RecvCommand))
    {
        std::string EncryptedMy;
        std::string EncMsg;
        EncMsg = parseEncMyMsg(RecvCommand);
        EncryptedMy = Enc(ThisUserLogin,EncMsg);
        SendCommand = ENCMY+EncryptedMy;
    }
    if(isEncryptOtherCommand(RecvCommand))
    {
        std::string EncOtherMsg;
        std::string Encrypted;
        std::string OtherLogin = parseEncOtherLogin(RecvCommand);
        EncOtherMsg = parseEncOtherMessage(RecvCommand);
        Encrypted = Enc(":"+OtherLogin,EncOtherMsg);
        SendCommand = ENCOther+Encrypted;
    }
    client.sendData(SendCommand.c_str(),SendCommand.size());
    db.SaveDB();
},

[](TcpServer::Client& client) { // Connect handler
  std::cout << "Client " << getHostStr(client) << " connected\n";

   
},


[](TcpServer::Client& client) { // Disconnect handler
  std::cout << "Client " << getHostStr(client) << " disconnected\n";

},

{1, 1, 1} // Keep alive{idle:1s, interval: 1s, pk_count: 1}
);

void testServer() {
  //Start server
  if(server.start() == TcpServer::status::up) {
      std::cout<<"Server listen on port:"<<server.getPort()<<std::endl;
      server.joinLoop();
      
  } else {
      std::cout<<"Server start error! Error code:"<< int(server.getStatus()) <<std::endl;
  }
}

int main() {
  using namespace std::chrono_literals;
  try {
  testServer();

  std::this_thread::sleep_for(10s);
  } catch(std::exception& except) {
    std::cerr << except.what();
  }
}