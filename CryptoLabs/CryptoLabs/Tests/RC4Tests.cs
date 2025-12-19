namespace CryptoLabs.Tests;
using RC4;
using System.Text;


public class RC4Tests
{
    public static void RunTests()
    {
        TestWithFiles();
    }
    
    
    public static void BasicTest()
    {
        var rc4 = new RC4Algorithm();
        
        var key = Encoding.UTF8.GetBytes("mySecretKey");
        var originalText = "Hello from RC4!";
        
        var inputData =  Encoding.UTF8.GetBytes(originalText);
        
        rc4.Initialize(key);
        var encrypted =  rc4.Encrypt(inputData);
        
        rc4.Initialize(key);
        var decrypted = rc4.Decrypt(encrypted);
        
        var decryptedText = Encoding.UTF8.GetString(decrypted);
        Console.WriteLine(decryptedText);
        
        TestsUtils.AssertEqualBlocks(inputData, decrypted, "RC4" + nameof(BasicTest));
    }

    
    public static void TestWithFiles()
    {
        var key = Encoding.UTF8.GetBytes("mySecretKey");
        RC4Algorithm.EncryptFile(TestFilePaths.mountain_input, TestFilePaths.mountain_encrypted, key, 4096);
        RC4Algorithm.DecryptFile(TestFilePaths.mountain_encrypted, TestFilePaths.mountain_output, key, 4096);
    }

    
    public static async Task SimpleAsyncTest()
    {
        var key = Encoding.UTF8.GetBytes("mySecretKey");
        await RC4Algorithm.EncryptFileAsync(TestFilePaths.mountain_input, TestFilePaths.mountain_encrypted, key, 4096);
        await RC4Algorithm.DecryptFileAsync(TestFilePaths.mountain_encrypted, TestFilePaths.mountain_output, key, 4096);
    }
    
    
    public static void RandomTest()
    {
        var rc4 = new RC4Algorithm();
        
        var random = new Random();
        
        var totalTests = 100;
        var passedTests = 0;
        var failedTests = 0;
        
        byte[] key = [0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD];
        
        for (var testNumber = 0; testNumber < totalTests; testNumber++)
        {
            var testData = GenerateRandomTestData(random);
            
            try
            {
                rc4.Initialize(key);
                var encrypted = rc4.Encrypt(testData);
                
                rc4.Initialize(key);
                var decrypted = rc4.Decrypt(encrypted);
                
                TestsUtils.AssertEqualBlocks(testData, decrypted, "RC4" + nameof(RandomTest));
                passedTests++;
            }
            
            catch (Exception ex)
            {
                failedTests++;
            }
        }
        Console.WriteLine($"passed tests: {passedTests}");
        Console.WriteLine($"failed tests: {failedTests}");
    }
    
    
    private static byte[] GenerateRandomTestData(Random random)
    {
        var dataLength = random.Next(1, 65);
        var data = new byte[dataLength];
        for (var i = 0; i < dataLength; i++)
        {
            data[i] = (byte)random.Next(256);
        }

        return data;
    }
}