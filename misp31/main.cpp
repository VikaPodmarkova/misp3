#include <iostream>
#include <string>
#include <UnitTest++/UnitTest++.h>
#include "modAlphaCipher.h"
struct fixture {
    modAlphaCipher* p;
    fixture()
    {
        p = new modAlphaCipher(L"Ã");
    }
    ~fixture()
    {
        delete p;
    }
};
SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK(modAlphaCipher(L"ß").encrypt(L"ÈÁÑÒ") == L"ÇÀĞÑ");
    }
    TEST(LongKey) {
        CHECK(modAlphaCipher(L"ßÑÔÈÒİ").encrypt(L"ÈÁÑÒ") == L"ÇÒ¨Û");
    }
    TEST(LowCaseKey) {
        CHECK(modAlphaCipher(L"ÿ").encrypt(L"ÈÁÑÒ") == L"ÇÀĞÑ");
    }
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher(L"ÔÈÒİ1"), cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher(L"Ô.È,Ò;İ"), cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher(L"È Á Ñ Ò"), cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher(L""), cipher_error);
    }
};
SUITE(EncryptTest)
{
    TEST_FIXTURE(fixture, UpCaseString) {
        CHECK(L"ÆÅÃÆÙÃÕßÆÅÃ" == p->encrypt(L"ÄÂÀÄÖÀÒÜÄÂÀ"));
    }
    TEST_FIXTURE(fixture, LowCaseString) {
        CHECK(L"ÆÅÃÆÙÃÕßÆÅÃ" == p->encrypt(L"äâàäöàòüäâà"));
    }
    TEST_FIXTURE(fixture, WhitSpace) {
        CHECK(L"ÆÅÃÆÙÃÕßÆÅÃ" == p->encrypt(L"ÄÂÀÄÖÀÒÜ ÄÂÀ"));
    }
    TEST_FIXTURE(fixture, Numbers) {
        CHECK(L"ÒË" == p->encrypt(L"22ÏÈ2"));
    }
    TEST_FIXTURE(fixture, Empty) {
        CHECK_THROW(p->encrypt(L""), cipher_error);
    }
    TEST_FIXTURE(fixture, NoAlpha) {
        CHECK_THROW(p->encrypt(L"23445567"), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK(L"ÃÁßÃÕßÑÛÃÁßÎÇŞ" == modAlphaCipher(L"ß").encrypt(L"ÄÂÀÄÖÀÒÜÄÂÀÏÈß"));
    }
};
SUITE(DecryptTest)
{
    TEST_FIXTURE(fixture, UpCaseString) {
        CHECK(L"ÄÂÀÄÖÀÒÜÄÂÀÏÈ" == p->decrypt(L"ÆÅÃÆÙÃÕßÆÅÃÒË"));
    }
    TEST_FIXTURE(fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"æåãæùãõÿæåãòë"), cipher_error);
    }
    TEST_FIXTURE(fixture, WhitSpace) {
        CHECK_THROW(p->decrypt(L"ÄÂÀÄÖÀÒÜ ÄÂÀ ÏÈ"), cipher_error);
    }
    TEST_FIXTURE(fixture, Digit) {
        CHECK_THROW(p->decrypt(L"22ÏÈ2"), cipher_error);
    }
    TEST_FIXTURE(fixture, Punct) {
        CHECK_THROW(p->decrypt(L"Ô.È,Ò;İ"), cipher_error);
    }
    TEST_FIXTURE(fixture, Empty) {
        CHECK_THROW(p->decrypt(L""), cipher_error);
    }
    TEST_FIXTURE(fixture, NoAlpha) {
        CHECK_THROW(p->decrypt(L"23445567"), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK(L"ÄÂÀÄÖÀÒÜÄÂÀÏÈß" == modAlphaCipher(L"ß").decrypt(L"ÃÁßÃÕßÑÛÃÁßÎÇŞ"));
    }
};
int main()
{
    std::locale loc("ru_RU.UTF-8");
    std::locale::global(loc);
    return UnitTest::RunAllTests();
}
