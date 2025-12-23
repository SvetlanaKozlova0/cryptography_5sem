namespace CryptoLabs.Tests;
using DES;
using Utility.CipherModes;
using Utility.Paddings;
using Utility.CryptoContext;
using Utility.Interfaces;

public class DESTests
{
    public static void RunTests()
    {
      TestJPGFile();
    }
    
    
    public static void DESTest1()
    {
        byte[][] keys = [ 
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 1
            [0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19], // 2
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // 3
            [0x45, 0x38, 0x12, 0x19, 0x91, 0x58, 0x23, 0xFF], // 4
            [0x98, 0x45, 0x29, 0x81, 0x75, 0x35, 0x28, 0xF2], // 5
            [0x01, 0x93, 0x56, 0x23, 0x65, 0x87, 0x88, 0x54], // 6
            [0x93, 0xFA, 0xAF, 0x34, 0x00, 0xED, 0xDE, 0x65], // 7
            [0x89, 0x45, 0x23, 0x32, 0x29, 0x65, 0x89, 0x37], // 8
            [0x90, 0x78, 0x87, 0x30, 0x21, 0x89, 0x34, 0x56], // 9
            [0x98, 0x54, 0x86, 0x36, 0x29, 0x18, 0x19, 0x45], // 10
            [0x78, 0x59, 0x26, 0x16, 0x78, 0x37, 0x64, 0x95], // 11
            [0x89, 0x78, 0x43, 0x58, 0x21, 0x75, 0xAE, 0x65], // 12
            [0x93, 0x99, 0xFA, 0xEE, 0x15, 0x65, 0x23, 0x65], // 13
            [0x89, 0x58, 0x78, 0x24, 0x43, 0x56, 0x82, 0x72], // 14
            [0x98, 0x43, 0x98, 0x75, 0x58, 0x27, 0x17, 0x37], // 15
            [0x18, 0x75, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], // 16
            [0x00, 0xFF, 0xDD, 0xEE, 0xAA, 0xCC, 0xEE, 0xBB], // 17
            [0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02], // 18
            [0x34, 0x89, 0x93, 0x82, 0x15, 0x72, 0x18, 0x19], // 19
            [0x52, 0x72, 0x94, 0x34, 0x64, 0x51, 0x76, 0x28]  // 20
        ];
        byte[][] data =
        [
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  // 1
            [0x01, 0x13, 0x15, 0x02, 0x06, 0x56, 0x32, 0xCC],  // 2
            [0xAA, 0x00, 0x54, 0x32, 0x07, 0x00, 0x23, 0x00],  // 3
             [0x90, 0xBB, 0x45, 0xAF, 0xDD, 0xAA, 0x43, 0x12], // 4
             [0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25], // 5
             [0x90, 0x45, 0x23, 0x56, 0x78, 0x90, 0x76, 0x45], // 6
             [0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45], // 7
             [0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x49], // 8
             [0x18, 0x56, 0x19, 0x45, 0x54, 0x76, 0x89, 0x12], // 9
             [0x90, 0x56, 0x89, 0x45, 0xAC, 0xCA, 0xFF, 0x65], // 10
             [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // 11
             [0x56, 0x34, 0x43, 0x72, 0x69, 0x21, 0xA7, 0x54], // 12
             [0x84, 0x3A, 0x34, 0xFF, 0x00, 0x23, 0x56, 0x89], // 13
             [0x12, 0x78, 0x12, 0x78, 0x12, 0x78, 0x12, 0x78], // 14
             [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // 15
             [0x19, 0x78, 0x14, 0x72, 0x89, 0x45, 0x89, 0x12], // 16
             [0x84, 0x38, 0xFA, 0xBC, 0xCD, 0xDD, 0xFF, 0x0F], // 17
             [0x78, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x87], // 18
             [0x56, 0x82, 0xFA, 0xBA, 0x45, 0x12, 0x34, 0xFF], // 19
             [0xBC, 0xBB, 0xDF, 0xAD, 0x12, 0xDD, 0xBD, 0xFF]  // 20
        ];
        
        for (int i = 0; i < data.Length; i++)
        {
            DESKeyExpander expander = new DESKeyExpander();
            byte[][] roundKeys = expander.GenerateRoundKeys(keys[i]);
            DESAlgorithm alg = new DESAlgorithm(roundKeys);
            byte[] encrypted = alg.Encrypt(data[i]);
            byte[] decrypted = alg.Decrypt(encrypted);
            TestsUtils.AssertEqualBlocks(data[i], decrypted, nameof(DESTest1));
        }
    }
    
    
    public static void DESTestRandomVectors()
    {
        var random = new Random();
        int tests = 100;
        int passed = 0;

        for (int i = 0; i < tests; i++)
        {
            byte[] key = new byte[8];
            byte[] data = new byte[8];
            random.NextBytes(key);
            random.NextBytes(data);

            var expander = new DESKeyExpander();
            var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
        
            if (data.SequenceEqual(alg.Decrypt(alg.Encrypt(data))))
                passed++;
        }

        Console.WriteLine($"Random vectors: {passed}/{tests} passed");
        if (passed < tests) throw new Exception("Random vector tests failed");
    }
    
    
    public static void DESRandomModesTest()
    {
        var random = new Random();
        int tests = 20;
        for (int i = 0; i < tests; i++)
        {
            byte[] key = new byte[8];
            byte[] data = new byte[32];
            byte[] iv = new byte[8];
            random.NextBytes(key);
            random.NextBytes(data);
            random.NextBytes(iv);
            var expander = new DESKeyExpander();
            var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
            var mode = CipherModeFactory.Create(CipherMode.ECB);
            byte[] encrypted = mode.Encrypt(alg, data, iv);
            byte[] decrypted = mode.Decrypt(alg, encrypted, iv);
            TestsUtils.AssertEqualBlocks(data, decrypted, nameof(DESRandomModesTest));
        }
        for (int i = 0; i < tests; i++)
        {
            byte[] key = new byte[8];
            byte[] data = new byte[32];
            byte[] iv = new byte[8];
            random.NextBytes(key);
            random.NextBytes(data);
            random.NextBytes(iv);
            var expander = new DESKeyExpander();
            var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
            var mode = CipherModeFactory.Create(CipherMode.CBC);
            byte[] encrypted = mode.Encrypt(alg, data, iv);
            byte[] decrypted = mode.Decrypt(alg, encrypted, iv);
            TestsUtils.AssertEqualBlocks(data, decrypted, nameof(DESRandomModesTest));
        }
        for (int i = 0; i < tests; i++)
        {
            byte[] key = new byte[8];
            byte[] data = new byte[32];
            byte[] iv = new byte[8];
            random.NextBytes(key);
            random.NextBytes(data);
            random.NextBytes(iv);
            var expander = new DESKeyExpander();
            var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
            var mode = CipherModeFactory.Create(CipherMode.PCBC);
            byte[] encrypted = mode.Encrypt(alg, data, iv);
            byte[] decrypted = mode.Decrypt(alg, encrypted, iv);
            TestsUtils.AssertEqualBlocks(data, decrypted, nameof(DESRandomModesTest));
        }
        for (int i = 0; i < tests; i++)
        {
            byte[] key = new byte[8];
            byte[] data = new byte[32];
            byte[] iv = new byte[8];
            random.NextBytes(key);
            random.NextBytes(data);
            random.NextBytes(iv);
            var expander = new DESKeyExpander();
            var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
            var mode = CipherModeFactory.Create(CipherMode.CFB);
            byte[] encrypted = mode.Encrypt(alg, data, iv);
            byte[] decrypted = mode.Decrypt(alg, encrypted, iv);
            TestsUtils.AssertEqualBlocks(data, decrypted, nameof(DESRandomModesTest));
        }
        for (int i = 0; i < tests; i++)
        {
            byte[] key = new byte[8];
            byte[] data = new byte[32];
            byte[] iv = new byte[8];
            random.NextBytes(key);
            random.NextBytes(data);
            random.NextBytes(iv);
            var expander = new DESKeyExpander();
            var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
            var mode = CipherModeFactory.Create(CipherMode.OFB);
            byte[] encrypted = mode.Encrypt(alg, data, iv);
            byte[] decrypted = mode.Decrypt(alg, encrypted, iv);
            TestsUtils.AssertEqualBlocks(data, decrypted, nameof(DESRandomModesTest));
        }
        for (int i = 0; i < tests; i++)
        {
            byte[] key = new byte[8];
            byte[] data = new byte[32];
            byte[] iv = new byte[8];
            random.NextBytes(key);
            random.NextBytes(data);
            random.NextBytes(iv);
            var expander = new DESKeyExpander();
            var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
            var mode = CipherModeFactory.Create(CipherMode.CTR);
            byte[] encrypted = mode.Encrypt(alg, data, iv);
            byte[] decrypted = mode.Decrypt(alg, encrypted, iv);
            TestsUtils.AssertEqualBlocks(data, decrypted, nameof(DESRandomModesTest));
        }
        for (int i = 0; i < tests; i++)
        {
            byte[] key = new byte[8];
            byte[] data = new byte[32];
            byte[] iv = new byte[8];
            random.NextBytes(key);
            random.NextBytes(data);
            random.NextBytes(iv);
            var expander = new DESKeyExpander();
            var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
            var mode = CipherModeFactory.Create(CipherMode.RandomDelta);
            byte[] encrypted = mode.Encrypt(alg, data, iv);
            byte[] decrypted = mode.Decrypt(alg, encrypted, iv);
            TestsUtils.AssertEqualBlocks(data, decrypted, nameof(DESRandomModesTest));
        }
    }
 
    
    public static void SimpleTest()
    {
        byte[] key = [ 0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD ];
        byte[] testData = [ 0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36 ];
        
        Console.WriteLine($"original key: {BitConverter.ToString(key)}");
        Console.WriteLine($"original data: {BitConverter.ToString(testData)}");
        Console.WriteLine();
    
        var expander = new DESKeyExpander();
        var roundKeys = expander.GenerateRoundKeys(key);
    
        Console.WriteLine("round keys:");
        for (var i = 0; i < roundKeys.Length; i++)
        {
            Console.WriteLine($"  round {i + 1,2}: {BitConverter.ToString(roundKeys[i])}");
        }
        Console.WriteLine();
    
        var alg = new DESAlgorithm(roundKeys);
    
        var encrypted = alg.Encrypt(testData);
        var decrypted = alg.Decrypt(encrypted);
    
        Console.WriteLine($"encrypted data: {BitConverter.ToString(encrypted)}");
        Console.WriteLine($"decrypted data: {BitConverter.ToString(decrypted)}");
        Console.WriteLine();
    
        TestsUtils.AssertEqualBlocks(testData, decrypted, nameof(SimpleTest));
    
        Console.WriteLine("everything is okay :)");
        Console.WriteLine();
    }
    
    
    public static void TestECBMode()
    {
        byte[] key = [ 0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD ];
        byte[] testData = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x18, 0x56, 0x19, 0x45, 0x54, 0x76, 0x89, 0x12,
            0x56, 0x82, 0xFA, 0xBA, 0x45, 0x12, 0x34, 0xFF];
        var expander = new DESKeyExpander();
        var roundKeys = expander.GenerateRoundKeys(key);
        var alg = new DESAlgorithm(roundKeys);
        var mode = CipherModeFactory.Create(CipherMode.ECB);
        var encrypted = mode.Encrypt(alg, testData, []);
        var decrypted = mode.Decrypt(alg, encrypted, []);
        TestsUtils.AssertEqualBlocks(testData, decrypted, nameof(TestECBMode));
    }
    
    
    public static void TestCipherModes()
    {
        byte[] key =  [ 0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD ];
        byte[] testData =
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1
            0x01, 0x13, 0x15, 0x02, 0x06, 0x56, 0x32, 0xCC, // 2
            0xAA, 0x00, 0x54, 0x32, 0x07, 0x00, 0x23, 0x00, // 3
            0x90, 0xBB, 0x45, 0xAF, 0xDD, 0xAA, 0x43, 0x12, // 4
            0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, // 5
            0x90, 0x45, 0x23, 0x56, 0x78, 0x90, 0x76, 0x45, // 6
            0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, // 7
            0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x49, // 8
            0x18, 0x56, 0x19, 0x45, 0x54, 0x76, 0x89, 0x12, // 9
            0x90, 0x56, 0x89, 0x45, 0xAC, 0xCA, 0xFF, 0x65, // 10
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 11
            0x56, 0x34, 0x43, 0x72, 0x69, 0x21, 0xA7, 0x54, // 12
            0x84, 0x3A, 0x34, 0xFF, 0x00, 0x23, 0x56, 0x89, // 13
            0x12, 0x78, 0x12, 0x78, 0x12, 0x78, 0x12, 0x78, // 14
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // 15
            0x19, 0x78, 0x14, 0x72, 0x89, 0x45, 0x89, 0x12, // 16
            0x84, 0x38, 0xFA, 0xBC, 0xCD, 0xDD, 0xFF, 0x0F, // 17
            0x78, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x87, // 18
            0x56, 0x82, 0xFA, 0xBA, 0x45, 0x12, 0x34, 0xFF, // 19
            0xBC, 0xBB, 0xDF, 0xAD, 0x12, 0xDD, 0xBD, 0xFF  // 20
        ];
        byte[] initialVector = [0x12, 0x34, 0x12, 0x78, 0x89, 0xFF, 0x45, 0x32];
        var modes = new[] {CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC,
            CipherMode.CFB, CipherMode.OFB, CipherMode.CTR, CipherMode.RandomDelta
        };
        var expander = new DESKeyExpander();
        var roundKeys =  expander.GenerateRoundKeys(key);
        var alg = new DESAlgorithm(roundKeys);
        foreach (var currentMode in modes)
        {
            try
            {
                var mode = CipherModeFactory.Create(currentMode);
                var encrypted = mode.Encrypt(alg, testData, initialVector);
                var decrypted = mode.Decrypt(alg, encrypted, initialVector);
                TestsUtils.AssertEqualBlocks(testData, decrypted, nameof(currentMode));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }
        }
    }
    
    
    public static void TestDES1()
    {
        byte[] key =  [ 0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD ];
        byte[] testData =
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1
            0x01, 0x13, 0x15, 0x02, 0x06, 0x56, 0x32, 0xCC, // 2
            0xAA, 0x00, 0x54, 0x32, 0x07, 0x00, 0x23, 0x00, // 3
            0x90, 0xBB, 0x45, 0xAF, 0xDD, 0xAA, 0x43, 0x12, // 4
            0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, // 5
            0x90, 0x45, 0x23, 0x56, 0x78, 0x90, 0x76, 0x45, // 6
            0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, // 7
            0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x49, // 8
            0x18, 0x56, 0x19, 0x45, 0x54, 0x76, 0x89, 0x12, // 9
            0x90, 0x56, 0x89, 0x45, 0xAC, 0xCA, 0xFF, 0x65, // 10
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 11
            0x56, 0x34, 0x43, 0x72, 0x69, 0x21, 0xA7, 0x54, // 12
            0x84, 0x3A, 0x34, 0xFF, 0x00, 0x23, 0x56, 0x89, // 13
            0x12, 0x78, 0x12, 0x78, 0x12, 0x78, 0x12, 0x78, // 14
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // 15
            0x19, 0x78, 0x14, 0x72, 0x89, 0x45, 0x89, 0x12, // 16
            0x84, 0x38, 0xFA, 0xBC, 0xCD, 0xDD, 0xFF, 0x0F, // 17
            0x78, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x87, // 18
            0x56, 0x82, 0xFA, 0xBA, 0x45, 0x12, 0x34, 0xFF, // 19
            0xBC, 0xBB, 0xDF, 0xAD, 0x12, 0xDD, 0xBD, 0xFF  // 20
        ];
        byte[] initialVector = [0x12, 0x34, 0x12, 0x78, 0x89, 0xFF, 0x45, 0x32];
        var expander = new DESKeyExpander();
        var roundKeys =  expander.GenerateRoundKeys(key);
        var alg = new DESAlgorithm(roundKeys);
        var context = new SymmetricCryptoContext(key, alg, CipherMode.ECB, PaddingMode.Zeros,
            expander, initialVector);
        var encrypted = context.EncryptSync(testData);
        var decrypted = context.DecryptSync(encrypted);
        TestsUtils.AssertEqualBlocks(testData, decrypted, nameof(TestDES1));
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

        
    public static void RunOneTest(byte[] key, byte[] iv, CipherMode mode,
        PaddingMode padding, byte[] data, ISymmetricCipher alg, IKeyExpander expander)
    {
        try
        {
            var context = new SymmetricCryptoContext(key, alg, mode, padding, expander, iv);
            var encrypted = context.EncryptSync(data);
            var decrypted = context.DecryptSync(encrypted);
            TestsUtils.AssertEqualBlocks(data, decrypted, nameof(RunOneTest));
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            throw;
        }
    }

    
    public static void TestRandomModesAndPaddings()
    {
        var random = new Random();
        var totalTests = 100;
        var passedTests = 0;
        var failedTests = 0;
        var allCipherModes = new[]
        {
            CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC, CipherMode.CFB,
            CipherMode.OFB, CipherMode.CTR, CipherMode.RandomDelta
        };
        var allPaddingModes = new[]
        {
            PaddingMode.Zeros, PaddingMode.ANSI_X923, PaddingMode.ISO10126, PaddingMode.PKCS7
        };
        byte[] key = [0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD];
        byte[] iv = [0x12, 0x34, 0x12, 0x78, 0x89, 0xFF, 0x45, 0x32];
        var expander = new DESKeyExpander();
        var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
        for (var testNumber = 0; testNumber < totalTests; testNumber++)
        {
            try
            {
                var mode = allCipherModes[random.Next(allCipherModes.Length)];
                var padding = allPaddingModes[random.Next(allPaddingModes.Length)];
                var testData = GenerateRandomTestData(random);
                Console.WriteLine($"\n--- Test {testNumber}/{totalTests} ---");
                Console.WriteLine($"Mode: {mode}, Padding: {padding}, Data length: {testData.Length} bytes");
                RunOneTest(key, iv, mode, padding, testData, alg, expander);
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

    
    public static void TestTXTFile()
    {
        byte[] key =  [ 0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD ];

        byte[] iv = [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF ];
        
        var expander = new DESKeyExpander();
        var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
        var cryptoContext = new SymmetricCryptoContext(key, alg, CipherMode.OFB, PaddingMode.PKCS7, expander, iv);
        cryptoContext.EncryptFile(TestFilePaths.text_input, TestFilePaths.text_encrypted);
        cryptoContext.DecryptFile(TestFilePaths.text_encrypted, TestFilePaths.text_output);
    }

    
    public static void TestJPGFile()
    {
        byte[] key = [ 0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD ];
        byte[] iv = [0x12, 0x34, 0x12, 0x78, 0x89, 0xFF, 0x45, 0x32];
        var expander = new DESKeyExpander();
        var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
        var context = new SymmetricCryptoContext(key, alg, CipherMode.RandomDelta, PaddingMode.PKCS7, expander, iv);
        context.EncryptFile(TestFilePaths.mountain_input, TestFilePaths.mountain_encrypted);
        context.DecryptFile(TestFilePaths.mountain_encrypted, TestFilePaths.mountain_output);
    }

    public static async Task TestAsync()
    {
        byte[] key = [ 0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD ];
        byte[] iv = [0x12, 0x34, 0x12, 0x78, 0x89, 0xFF, 0x45, 0x32];
        var expander = new DESKeyExpander();
        var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
        var context = new SymmetricCryptoContext(key, alg, CipherMode.RandomDelta, PaddingMode.PKCS7, expander, iv);
        await context.EncryptFileAsync(TestFilePaths.mountain_input, TestFilePaths.mountain_encrypted);
        await context.DecryptFileAsync(TestFilePaths.mountain_encrypted, TestFilePaths.mountain_output);
    }
    
    public static async Task TestAsyncSecond()
    {
        byte[] key = [ 0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD ];
        byte[] iv = [0x12, 0x34, 0x12, 0x78, 0x89, 0xFF, 0x45, 0x32];
        var expander = new DESKeyExpander();
        var alg = new DESAlgorithm(expander.GenerateRoundKeys(key));
        var context = new SymmetricCryptoContext(key, alg, CipherMode.RandomDelta, PaddingMode.PKCS7, expander, iv);
        await context.EncryptFileAsync(TestFilePaths.text_input, TestFilePaths.text_encrypted);
        await context.DecryptFileAsync(TestFilePaths.text_encrypted, TestFilePaths.text_output);
    }
}