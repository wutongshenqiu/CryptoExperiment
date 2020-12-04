#include <bitset>
#include "des.hpp"
#include "rijndael.hpp"
#include "utils.hpp"


int main() {
    using namespace std;

    bitset<64> key("0011000100110010001100110011010000110101001101100011011100111000");
    bitset<64> text("0011000000110001001100100011001100110100001101010011011000110111");
    bitset<64> ciphertext("1000101110110100011110100000110011110000101010010110001001101101");
    DES test;
    test.SetKey(key);

    assert(ciphertext == test.Encrypt(text));
    assert(text == test.Decrypt(ciphertext));


    array<uint8_t, 16> aes_key = {0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6d, 0x79,
                                  0x20, 0x4b, 0x75, 0x6e, 0x67, 0x20, 0x46, 0x75};
    array<uint8_t, 16> aes_message = {0x54, 0x77, 0x6f, 0x20, 0x4f, 0x6e, 0x65, 0x20,
                                      0x4e, 0x69, 0x6e, 0x65, 0x20, 0x54, 0x77, 0x6f};
    RijnDael rijndael(aes_key);
    auto rijndael_ciphertext = rijndael.encrypt(aes_message);
    assert (aes_message == rijndael.decrypt(rijndael_ciphertext));

    return 0;
}
