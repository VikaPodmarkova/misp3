#pragma once
#include <iostream>
#include <cstring>
#include <cctype>
#include <string>
#include <locale>
#include <codecvt>
#include <vector>
#include <map>
#include <locale.h>
using namespace std;
locale loc("ru_RU.UTF-8");
wstring_convert<codecvt_utf8<wchar_t>, wchar_t> codec;

class locale;
class modAlphaCipher
{
private:

    wstring numAlpha = L"ÀÁÂÃÄÅ¨ÆÇÈÉÊËÌÍÎÏĞÑÒÓÔÕÖ×ØÙÚÛÜİŞß";
    map <char, int> alphaNum;
    vector <int> key; //êëş÷
    vector <int> convert(const string& s);
    string convert(const vector<int>& v);
    string getValidKey(const string& s);
    string getValidOpenText(const string& s);
    string getValidCipherText(const string& s);
public:
    modAlphaCipher() = delete;
    modAlphaCipher(const std::string& skey);
    std::string encrypt(const std::string& open_text);
    std::string decrypt(const std::string& cipher_text);
};
class cipher_error : public std::invalid_argument
{
public:
    explicit cipher_error(const std::string& what_arg) :
        std::invalid_argument(what_arg) {}
    explicit cipher_error(const char* what_arg) :
        std::invalid_argument(what_arg) {}
};