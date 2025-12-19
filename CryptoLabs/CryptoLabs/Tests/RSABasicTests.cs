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

    public static async Task TestAsync()
    {
        var rsaService = new RSACipherService(
            RSACipherService.PrimalityTestType.Fermat,
            0.999,
            2048);

        var keyPair = rsaService.GenerateKeyPair();
        
        byte[] original =
        [
            0x01, 0x02, 0x03, 0x04,
            0x10, 0x20, 0x30,
            0xFF, 0x00, 0xAA
        ];

        await File.WriteAllBytesAsync(TestFilePaths.rsa_input, original);

        await rsaService.EncryptFileAsync(TestFilePaths.rsa_input, TestFilePaths.rsa_encrypted, keyPair.PublicKey);

        await rsaService.DecryptFileAsync(TestFilePaths.rsa_encrypted, TestFilePaths.rsa_output, keyPair.PrivateKey);

        byte[] a = await File.ReadAllBytesAsync(TestFilePaths.rsa_input);
        byte[] b = await File.ReadAllBytesAsync(TestFilePaths.rsa_output);

        Console.WriteLine("input:  " + BitConverter.ToString(a));
        Console.WriteLine("output: " + BitConverter.ToString(b));
        Console.WriteLine("equal:  " + a.SequenceEqual(b));
    }

    public static async Task TestAsyncSecond()
    {
        var rsaService = new RSACipherService( RSACipherService.PrimalityTestType.Fermat, 0.999, 2048);
        var keyPair = rsaService.GenerateKeyPair(); 
        await rsaService.EncryptFileAsync( TestFilePaths.text_input, TestFilePaths.text_encrypted, keyPair.PublicKey);
        await rsaService.DecryptFileAsync( TestFilePaths.text_encrypted, TestFilePaths.text_output, keyPair.PrivateKey); 
    }
}