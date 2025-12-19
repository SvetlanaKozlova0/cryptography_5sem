namespace CryptoLabs.Tests;
using RSA;
using System.Text;


public class RSABasicTests
{
    public static void RunMyTests()
    {
        SimpleTest();
    }
    
    private static void SimpleTest()
    {
        var rsaService = new RSACipherService(RSACipherService.PrimalityTestType.Fermat,
            0.99, 512);
        
        var keyPair = rsaService.GenerateKeyPair();
        
        var originalMessage = "dflkdsjfiemflskfoiejfls___flksjflsf**";
        var originalBytes = Encoding.UTF8.GetBytes(originalMessage);

        var encrypted = rsaService.Encrypt(originalBytes, keyPair.PublicKey);
        var decrypted = rsaService.Decrypt(encrypted, keyPair.PrivateKey);
        
        TestsUtils.AssertEqualBlocks(originalBytes, decrypted, "RSA" + nameof(SimpleTest));
        var decryptedMessage = Encoding.UTF8.GetString(decrypted);
        Console.WriteLine($"decrypted message: {decryptedMessage}");
    }
    
}