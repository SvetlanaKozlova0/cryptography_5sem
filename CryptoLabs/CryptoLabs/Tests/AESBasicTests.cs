using CryptoLabs.Utility.CryptoContext;
using CipherMode = CryptoLabs.Utility.CipherModes.CipherMode;
using CryptoLabs.Utility.Paddings;

namespace CryptoLabs.Tests;
using CryptoLabs.AES.Utility;
using AES;

public class RijndaelBasicTests
{
    public static void RunTests()
    {
        BasicTest();
        Test_AllOnes();
        Test_AllZeros();
        Test_Checkerboard();
        Test_192();
        Test_256();
        //TestJPGFile();
    }
    
    public static void BasicTest()
    {
        var boxGenerator = new RijndaelBoxGenerator(0x1b);
        var aes = new RijndaelAlgorithm(boxGenerator);
        var keyExpander = new RijndaelKeyExpander(boxGenerator);
        byte[] key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        
        byte[] plaintext = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
        ];

        var roundKeys = keyExpander.GenerateRoundKeys(key);
        aes.SetRoundKeys(roundKeys);
        var cipherText = aes.Encrypt(plaintext);
        var decrypted = aes.Decrypt(cipherText);
        TestsUtils.AssertEqualBlocks(plaintext, decrypted, "AES" + nameof(BasicTest));
    }
    
    
    public static void Test_AllZeros()
    {
        var boxGenerator = new RijndaelBoxGenerator(0x1b);
        var aes = new RijndaelAlgorithm(boxGenerator);
        var keyExpander = new RijndaelKeyExpander(boxGenerator);
    
        var key = new byte[16]; 
        var plaintext = new byte[16]; 

        var roundKeys = keyExpander.GenerateRoundKeys(key);
        aes.SetRoundKeys(roundKeys);
        var cipherText = aes.Encrypt(plaintext);
        var decrypted = aes.Decrypt(cipherText);
        TestsUtils.AssertEqualBlocks(plaintext, decrypted, "AES" + nameof(Test_AllZeros));
    }
    
    
    public static void Test_AllOnes()
    {
        var boxGenerator = new RijndaelBoxGenerator(0x1b);
        var aes = new RijndaelAlgorithm(boxGenerator);
        var keyExpander = new RijndaelKeyExpander(boxGenerator);
    
        var key = Enumerable.Repeat((byte)0xFF, 16).ToArray();
        var plaintext = Enumerable.Repeat((byte)0xFF, 16).ToArray();

        var roundKeys = keyExpander.GenerateRoundKeys(key);
        aes.SetRoundKeys(roundKeys);
        var cipherText = aes.Encrypt(plaintext);
        var decrypted = aes.Decrypt(cipherText);
        TestsUtils.AssertEqualBlocks(plaintext, decrypted, "AES" + nameof(Test_AllOnes));
    }
    
    
    public static void Test_Checkerboard()
    {
        var boxGenerator = new RijndaelBoxGenerator(0x1b);
        var aes = new RijndaelAlgorithm(boxGenerator);
        var keyExpander = new RijndaelKeyExpander(boxGenerator);
    
        byte[] key = [0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 
            0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55];
        byte[] plaintext = [0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA,
            0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA];

        var roundKeys = keyExpander.GenerateRoundKeys(key);
        aes.SetRoundKeys(roundKeys);
        var cipherText = aes.Encrypt(plaintext);
        var decrypted = aes.Decrypt(cipherText);
        TestsUtils.AssertEqualBlocks(plaintext, decrypted, "AES" + nameof(Test_Checkerboard));
    }
    
    
    public static void Test_192()
    {
        var boxGenerator = new RijndaelBoxGenerator(0x1b);
        var aes = new RijndaelAlgorithm(boxGenerator);
        var keyExpander = new RijndaelKeyExpander(boxGenerator);
    
        byte[] key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
        ];
    
        byte[] plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ];

        var roundKeys = keyExpander.GenerateRoundKeys(key);
        aes.SetRoundKeys(roundKeys);
        var cipherText = aes.Encrypt(plaintext);
        var decrypted = aes.Decrypt(cipherText);
        TestsUtils.AssertEqualBlocks(plaintext, decrypted, "AES" + nameof(Test_192));
    }
    
    
    public static void Test_256()
    {
        var boxGenerator = new RijndaelBoxGenerator(0x1b);
        var aes = new RijndaelAlgorithm(boxGenerator);
        var keyExpander = new RijndaelKeyExpander(boxGenerator);
    
        byte[] key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
        ];
    
        byte[] plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ];

        var roundKeys = keyExpander.GenerateRoundKeys(key);
        aes.SetRoundKeys(roundKeys);
        var cipherText = aes.Encrypt(plaintext);
        var decrypted = aes.Decrypt(cipherText);
        TestsUtils.AssertEqualBlocks(plaintext, decrypted, "AES" + nameof(Test_256));
    }

    
    public static void TestTXTFile()
    {
        byte[] key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
        ];
        
        byte[] iv = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        
        var boxGenerator = new RijndaelBoxGenerator(0x1b);
        var aes = new RijndaelAlgorithm(boxGenerator);
        var keyExpander = new RijndaelKeyExpander(boxGenerator);

        var context = new SymmetricCryptoContext(key, aes, CipherMode.CTR, PaddingMode.PKCS7, keyExpander, iv);
        context.EncryptFile(TestFilePaths.text_input, TestFilePaths.text_encrypted);
        context.DecryptFile(TestFilePaths.text_encrypted,  TestFilePaths.text_output);
    }

    
    public static void TestJPGFile()
    {
        byte[] key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
        ];
        
        byte[] iv = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        
        var boxGenerator = new RijndaelBoxGenerator(0x1b);
        var aes = new RijndaelAlgorithm(boxGenerator);
        var keyExpander = new RijndaelKeyExpander(boxGenerator);

        var context = new SymmetricCryptoContext(key, aes, CipherMode.RandomDelta, PaddingMode.PKCS7, keyExpander, iv);
        context.EncryptFile(TestFilePaths.mountain_input, TestFilePaths.mountain_encrypted);
        context.DecryptFile(TestFilePaths.mountain_encrypted, TestFilePaths.mountain_output);
    }
}