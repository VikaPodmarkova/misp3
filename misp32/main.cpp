#include <iostream>
#include <string>
#include <UnitTest++/UnitTest++.h>
#include "modAlphaCipher.h"
SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("LLEHO", modAlphaCipher("4").encrypt("HELLO"));
    }
    TEST(LetterInKey) {
        CHECK_THROW(modAlphaCipher cp("Á1"), cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp("1,1"), cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp("1 2"), cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(""), cipher_error);
    }
    TEST(WeakKey) {
        CHECK_THROW(modAlphaCipher cp("1"), cipher_error);
    }
}

struct KeyB_fixture {
    modAlphaCipher* p;
    KeyB_fixture()
    {
        p = new modAlphaCipher("4");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("LRLOEWDHOL",
            p->encrypt("HELLOWORLD"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("LRLOEWDHOL",
            p->encrypt("helloworld"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("LRLOEWDHOL",
            p->encrypt("HELLO WORLD!!!"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("LRLOEWDHOL", p->encrypt("HELLO 2023 WORLD"));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(""), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt("1234+8765=9999"), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("DLROWOLLEH",
            modAlphaCipher("10").encrypt("HELLOWORLD"));
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("HELLOWORLD",
            p->decrypt("LRLOEWDHOL"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt("lrloeWDHOL"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt("LRLOE WDHOL"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt("LRLOE2021WDHOL"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt("LRLOE,WDHOL"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(""), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("HELLOWORLD",
            modAlphaCipher("10").decrypt("DLROWOLLEH"));
    }
}

int main(int argc, char** argv)
{
    return UnitTest::RunAllTests();
}
