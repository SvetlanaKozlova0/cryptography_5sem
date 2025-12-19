namespace CryptoLabs.Tests;
using CryptoLabs.TripleDES;
using CryptoLabs.Utility.CryptoContext;
using CryptoLabs.Utility.CipherModes;
using CryptoLabs.Utility.Paddings;

public class TripleDESTests
{
    public static void RunTests()
    {
        //BasicTest();
        //TestFileTXT();
        TestFileJPG();
    }
    
    
    public static void BasicTest()
    {
        var triple = new TripleDESAlgorithm();
        var keyExpander = new TripleDESKeyExpander();
        
        byte[] key192 = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67
        ];
        
        byte[] plaintext192 = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
        ];
        
        var roundKeys = keyExpander.GenerateRoundKeys(key192);
        triple.SetRoundKeys(roundKeys);
        
        var ciphertext = triple.Encrypt(plaintext192);
        var decrypted = triple.Decrypt(ciphertext);
        
        TestsUtils.AssertEqualBlocks(plaintext192, decrypted, "Triple DES" + nameof(BasicTest));
    }
    
    
    public static void TestFileTXT()
    {
        var deal = new TripleDESAlgorithm();
        var keyExpander = new TripleDESKeyExpander();
        
        byte[] key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];

        byte[] iv = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        
        var context = new SymmetricCryptoContext(key, deal, CipherMode.CTR, PaddingMode.PKCS7, keyExpander, iv);
        context.EncryptFile(TestFilePaths.text_input, TestFilePaths.text_encrypted);
        
        context.DecryptFile(TestFilePaths.text_encrypted, TestFilePaths.text_output);
    }

    
    public static void TestFileJPG()
    {
        var deal = new TripleDESAlgorithm();
        var keyExpander = new TripleDESKeyExpander();
        
        byte[] key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        byte[] iv = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        
        var context = new SymmetricCryptoContext(key, deal, CipherMode.OFB, PaddingMode.PKCS7, keyExpander, iv);
        
        context.EncryptFile(TestFilePaths.mountain_input, TestFilePaths.mountain_encrypted);
        context.DecryptFile(TestFilePaths.mountain_encrypted, TestFilePaths.mountain_output);    
    }
}