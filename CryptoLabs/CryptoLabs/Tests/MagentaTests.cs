using CryptoLabs.Magenta;
using CryptoLabs.Magenta.Utility;
using CryptoLabs.Utility.CryptoContext;
using CryptoLabs.Utility.CipherModes;
using CryptoLabs.Utility.Paddings;

namespace CryptoLabs.Tests;

public static class MagentaTests
{
    public static void RunTests()
    {
      // TestFileTxt();
       TestFileJpg();
    }
    
    
    public static void TestFileTxt()
    {
        var generator = new MagentaBoxGenerator(0x65);
        var magenta = new MagentaAlgorithm(generator);
        
        byte[] key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        byte[] iv = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        var keyExpander = new MagentaKeyExpander();
        
        var context = new SymmetricCryptoContext(key, magenta, CipherMode.CTR, PaddingMode.PKCS7, keyExpander, iv);

        context.EncryptFile(TestFilePaths.text_input, TestFilePaths.text_encrypted);
        context.DecryptFile(TestFilePaths.text_encrypted, TestFilePaths.text_output);
    }
    
    
    public static void TestFileJpg()
    {
        var generator = new MagentaBoxGenerator(0x65);
        var magenta = new MagentaAlgorithm(generator);
        
        byte[] key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        byte[] iv = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        var keyExpander = new MagentaKeyExpander();
        
        var context = new SymmetricCryptoContext(key, magenta, CipherMode.CTR, PaddingMode.PKCS7, keyExpander, iv);
        context.EncryptFile(TestFilePaths.mountain_input, TestFilePaths.mountain_encrypted);
        context.DecryptFile(TestFilePaths.mountain_encrypted, TestFilePaths.mountain_output);
    }
    
    
    public static void SimpleTest()
    {
        var generator = new MagentaBoxGenerator(0xA9);
        var magenta = new MagentaAlgorithm(generator);
        
        byte[] key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        byte[] plaintext192 = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF  
        ];
        
        var keyExpander = new MagentaKeyExpander();
        
        var roundKeys = keyExpander.GenerateRoundKeys(key);
        magenta.SetRoundKeys(roundKeys);
        
        var ciphertext = magenta.Encrypt(plaintext192);
        Console.WriteLine(ciphertext.Length);
        
        var decrypted = magenta.Decrypt(ciphertext);
        Console.WriteLine(decrypted.Length);
        
        TestsUtils.AssertEqualBlocks(plaintext192, decrypted, "Magenta" + nameof(SimpleTest));
    }
}