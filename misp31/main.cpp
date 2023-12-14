#include <iostream>
#include <string>
#include <UnitTest++/UnitTest++.h>
#include "modAlphaCipher.h"
struct fixture {
    modAlphaCipher* p;
    fixture()
    {
        p = new modAlphaCipher(L"�");
    }
    ~fixture()
    {
        delete p;
    }
};
SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK(modAlphaCipher(L"�").encrypt(L"����") == L"����");
    }
    TEST(LongKey) {
        CHECK(modAlphaCipher(L"������").encrypt(L"����") == L"�Ҩ�");
    }
    TEST(LowCaseKey) {
        CHECK(modAlphaCipher(L"�").encrypt(L"����") == L"����");
    }
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher(L"����1"), cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher(L"�.�,�;�"), cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher(L"� � � �"), cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher(L""), cipher_error);
    }
};
SUITE(EncryptTest)
{
    TEST_FIXTURE(fixture, UpCaseString) {
        CHECK(L"�����������" == p->encrypt(L"�����������"));
    }
    TEST_FIXTURE(fixture, LowCaseString) {
        CHECK(L"�����������" == p->encrypt(L"�����������"));
    }
    TEST_FIXTURE(fixture, WhitSpace) {
        CHECK(L"�����������" == p->encrypt(L"�������� ���"));
    }
    TEST_FIXTURE(fixture, Numbers) {
        CHECK(L"��" == p->encrypt(L"22��2"));
    }
    TEST_FIXTURE(fixture, Empty) {
        CHECK_THROW(p->encrypt(L""), cipher_error);
    }
    TEST_FIXTURE(fixture, NoAlpha) {
        CHECK_THROW(p->encrypt(L"23445567"), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK(L"��������������" == modAlphaCipher(L"�").encrypt(L"��������������"));
    }
};
SUITE(DecryptTest)
{
    TEST_FIXTURE(fixture, UpCaseString) {
        CHECK(L"�������������" == p->decrypt(L"�������������"));
    }
    TEST_FIXTURE(fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"�������������"), cipher_error);
    }
    TEST_FIXTURE(fixture, WhitSpace) {
        CHECK_THROW(p->decrypt(L"�������� ��� ��"), cipher_error);
    }
    TEST_FIXTURE(fixture, Digit) {
        CHECK_THROW(p->decrypt(L"22��2"), cipher_error);
    }
    TEST_FIXTURE(fixture, Punct) {
        CHECK_THROW(p->decrypt(L"�.�,�;�"), cipher_error);
    }
    TEST_FIXTURE(fixture, Empty) {
        CHECK_THROW(p->decrypt(L""), cipher_error);
    }
    TEST_FIXTURE(fixture, NoAlpha) {
        CHECK_THROW(p->decrypt(L"23445567"), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK(L"��������������" == modAlphaCipher(L"�").decrypt(L"��������������"));
    }
};
int main()
{
    std::locale loc("ru_RU.UTF-8");
    std::locale::global(loc);
    return UnitTest::RunAllTests();
}
