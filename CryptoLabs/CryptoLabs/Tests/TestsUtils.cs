namespace CryptoLabs.Tests;

public static class TestsUtils
{
    public static void AssertEqualBlocks(byte[] actual, byte[] expected, string testName)
    {
        if (actual.Length != expected.Length)
        {
            throw new Exception($"Test {testName} failed: Length mismatch - Expected {expected.Length}, got {actual.Length}");
        }

        for (int i = 0; i < actual.Length; i++)
        {
            if (actual[i] != expected[i])
            {
                throw new Exception($"Test {testName} failed at index {i}: Expected {expected[i]:X2}, got {actual[i]:X2}");
            }
        }
        Console.WriteLine($"✓ {testName}");
    }
    
    
    public static void AssertEqual(byte actual, byte expected, string testName)
    {
        if (actual != expected)
        {
            throw new Exception($"Test {testName} failed: Expected {expected:X2}, got {actual:X2}");
        }
        Console.WriteLine($"✓ {testName}");
    }
    
    
    private static void AssertEqualInts(int actual, int expected, string testName)
    {
        if (actual != expected)
        {
            throw new Exception($"Test {testName} failed: Expected {expected}, got {actual}");
        }
        Console.WriteLine($"✓ {testName}");
    }
}