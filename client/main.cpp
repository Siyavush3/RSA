#include "../tcp/hdr/TcpClient.h"
#include <iostream>
#include <fstream>
#include <thread>
#include<string>
#include<stdlib.h>
#include<unistd.h>
#include <cstring>
#include <sstream>
#define BUFFER_SIZE 1024
long long command;

std::string msg;
std::string OtherID;
std::string login;
std::string pass;
std:: string buffer ;
char bf[BUFFER_SIZE];
bool ClientValidated = false;
bool quit = false ;
std::string Mycommand;

const std::string  CREATE= "CREATE::";
const std::string  VALID= "VALID::";
const std::string CRYPT = "CRYPT::";
const std::string ENCMY = "ENC::";
const std::string ENCOther = "ENC_FROM_ID::";

std::string getHostStr(uint32_t ip, uint16_t port) 
{
    return std::string() + std::to_string(int(reinterpret_cast<char*>(&ip)[0])) + '.' +
            std::to_string(int(reinterpret_cast<char*>(&ip)[1])) + '.' +
            std::to_string(int(reinterpret_cast<char*>(&ip)[2])) + '.' +
            std::to_string(int(reinterpret_cast<char*>(&ip)[3])) + ':' +
            std::to_string( port );
}



void Menu()
{
    if(ClientValidated){
    std::cout<<"WellCome to digital signature app client.\n\n"<<std::endl;
    std::cout<<"Please choose what operation you wan't to do:\n";
    
    std:: cout<<"1)Press 1 if you wan't encrypt  message\n";
    std:: cout<<"2)Press 2 if you wan't decrypt your message\n";
    std:: cout<<"3)Press 3 if you wan't decrypt massage from login\n\n\n";
    std:: cout<<"3)Press 4 if you wan't quit app\n\n\n";
    std::  cout<<"Write a number of command here:";
    }
    else
    {
        std::cout<<"WellCome to digital signature app client.\n\n"<<std::endl;
        std::cout<<"Please choose what operation you wan't to do:\n";
        std:: cout<<"Press 1 if you wan't signin \n";
        std:: cout<<"Press 2 if you wan't signup\n";
    }


}




bool isCRYPTCommand(std::string_view message) {
    return message.find(CRYPT) == 0;
}
bool isValidCommand(std::string_view message) {
    return message.find(VALID) == 0;
}
bool isCREATECommand(std::string_view message) {
    return message.find(CREATE) == 0;
}
bool isEncryptMyCommand(std::string_view message) {
    return message.find(ENCMY) == 0;
}
bool isEncryptOtherCommand(std::string_view message) {
    return message.find(ENCOther) == 0;
}

std::string parseEncOther(std::string_view message) {
    std::string_view rest = message.substr(ENCOther.length());
    int pos = rest.find("::");
    std::string_view id = rest.substr(0, pos);
    return std::string(id);
}
std::string parseCREATE(std::string_view message) {
    std::string_view rest = message.substr(CREATE.length());
    int pos = rest.find("::");
    std::string_view id = rest.substr(0, pos);
    return std::string(id);
}
std::string parseValid(std::string_view message) {
    std::string_view rest = message.substr(VALID.length());
    int pos = rest.find("::");
    std::string_view id = rest.substr(0, pos);
    return std::string(id);
}

std::string parseEncMy(std::string_view message) {
    std::string_view rest = message.substr(ENCMY.length());
    int pos = rest.find("::");
    std::string_view id = rest.substr(0, pos);
    return std::string(id);
}



std::string parseCrypt(std::string_view message) {
    std::string_view rest = message.substr(CRYPT.length());
    int pos = rest.find("::");
    std::string_view id = rest.substr(0, pos);
    return std::string(id);
}


void client() {
    using namespace std::chrono_literals;
    TcpClient client;
    client.connectTo(LOCALHOST_IP, 8080);
    try
    {   
        while(!quit){    Menu();
            std::cin>>command;
          
        
            if(command == 1 && ClientValidated)
                {
                    std::cout<<"Input message what you want to crypt:";
                    std:: cin>>msg;
                    buffer = CRYPT + msg;
                }
            if(command == 2 && ClientValidated)
                {
                    std:: cout<<"Input your crypted message:";
                    std::  cin>>msg;
                    buffer = ENCMY + msg;
                }
            if(command == 3 && ClientValidated)
                {
                    std::  cout<<"Input login of the user, whose message you wan't encypt:";
                    std::  cin>>OtherID;
                    std::  cout<<"Input  crypted message:";
                    std::  cin>>msg;
                    buffer = ENCOther+OtherID+"::"+msg;
                }
            if(command == 1 && !ClientValidated)
                {
                    std:: cout<<"Login:";
                    std::  cin>>login;
                    std:: cout<<"Password:";
                    std::  cin>>pass;                    
                    buffer = VALID+login+"::"+pass;
                }
            if(command == 2 && !ClientValidated)
                {
                    std:: cout<<"Login:";
                    std::  cin>>login;
                    std:: cout<<"Password:";
                    std::  cin>>pass;                    
                    buffer = CREATE+login+"::"+pass;
                }
                


            client.sendData(buffer.c_str(), buffer.size());


            DataBuffer data = client.loadData();



           strcpy(bf,(char *) data.data_ptr);
           Mycommand = std::string(bf);
            

            if(isCRYPTCommand(Mycommand))
                {
                    std::string Crypted;
                    Crypted = parseCrypt(Mycommand);
                    std::cout<<"\nYour crypted message:"<<Crypted<<std::endl;

                }
            if(isEncryptMyCommand(Mycommand))
                {
                    std::string Encrypted;
                    Encrypted = parseEncMy(Mycommand);
                    std::cout<<"\nYour encrypted message:"<<Encrypted<<std::endl;


                }
            if(isEncryptOtherCommand(Mycommand))
                {
                    std::string Encrypted;
                    Encrypted = parseEncOther(Mycommand);
                    std::cout<<"\nOther user encrypted message:"<<Encrypted<<std::endl;
                }
            if(isCREATECommand(Mycommand))
                {
                    std::string create;
                    create = parseCREATE(Mycommand);
                    if(create=="Login_busy")
                    {
                        ClientValidated = false;
                    }
                    if(create=="User_created")
                    {
                        ClientValidated = true;
                    }
                    std::cout<<"\n"<<create<<std::endl;
                }
            if(isValidCommand(Mycommand))
                {
                    std::string valid;
                    valid = parseValid(Mycommand);
                    std::cout<<"\n"<<Mycommand<<std::endl;
                    if(valid=="WRONG_LOGIN_OR_PASSWORD")
                    {
                        ClientValidated = false;
                    }
                    if(valid=="VALIDATED")
                    {
                        ClientValidated = true;
                    }
                    std::cout<<"\n"<<valid<<std::endl;
                }


            std::this_thread::sleep_for(1s);
        }



        
    }
    catch(const std::exception& e)
    {
        std::cout<<e.what();
    }
}



int main() {
  std::thread th1(client);
   
  th1.join();

}