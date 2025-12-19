using CryptoLabs.Utility.CryptoContext;
using CryptoLabs.Utility.CipherModes;
using CryptoLabs.Utility.Paddings;

namespace CryptoLabs.Tests;
using DEAL;


public class DEALTests
{
    public static void RunTests()
    {
        //TestFileTXT();
        TestFileJPG();
    }
    
    public static void BasicTest()
    {
        var deal = new DealAlgorithm();
        var keyExpander = new DealKeyExpander();

        byte[] key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        byte[] plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        
        var roundKeys = keyExpander.GenerateRoundKeys(key);
        
        deal.SetRoundKeys(roundKeys);
        var ciphertext = deal.Encrypt(plaintext);
        
        var decrypted = deal.Decrypt(ciphertext);
        TestsUtils.AssertEqualBlocks(plaintext,  decrypted, "DEAL" + nameof(BasicTest));
    }

    
    public static void TestFileTXT()
    {
        var deal = new DealAlgorithm();
        var keyExpander = new DealKeyExpander();
        
        byte[] key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        byte[] iv = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        var context = new SymmetricCryptoContext(key, deal, CipherMode.RandomDelta, PaddingMode.PKCS7, keyExpander, iv);
        context.EncryptFile(TestFilePaths.text_input, TestFilePaths.text_encrypted);
        context.DecryptFile(TestFilePaths.text_encrypted, TestFilePaths.text_output);
    }

    
    public static void TestFileJPG()
    {
        var deal = new DealAlgorithm();
        var keyExpander = new DealKeyExpander();
        
        byte[] key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        byte[] iv = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        var context = new SymmetricCryptoContext(key, deal, CipherMode.RandomDelta, PaddingMode.PKCS7, keyExpander, iv);
        
        context.EncryptFile(TestFilePaths.mountain_input, TestFilePaths.mountain_encrypted);
        context.DecryptFile(TestFilePaths.mountain_encrypted, TestFilePaths.mountain_output);
    }
}