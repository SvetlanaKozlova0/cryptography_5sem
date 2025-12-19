namespace CryptoLabs.Tests;
using CryptoLabs.Utility.Paddings;


public class PaddingTests
{
    public static void RunTests()
    {
        
    }
    
    public static void TestZerosPaddingApply()
    {
        var padding = new ZerosPadding();
        byte[] input = [0x01, 0x02, 0x03];
        
        var result = padding.ApplyPadding(input, 8);
        byte[] expected = [0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        TestsUtils.AssertEqualBlocks(result, expected, nameof(TestZerosPaddingApply));
    }
    
    public static void TestZerosRemove()
    {
        var padding = new ZerosPadding();
        byte[] input = [0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        var result = padding.RemovePadding(input, 8);
        byte[] expected = [0x01, 0x02, 0x03];
        TestsUtils.AssertEqualBlocks(result, expected, nameof(TestZerosRemove));
    }

    public static void TestZerosAllCycle()
    {
        var padding = new ZerosPadding();
        byte[] original = [0x01, 0x02, 0x03, 0x04, 0x05];

        var padded = padding.ApplyPadding(original, 8);
        var unpadded = padding.RemovePadding(padded, 8);
        TestsUtils.AssertEqualBlocks(original, unpadded, nameof(TestZerosAllCycle));
    }
    
    public static void TestZerosPaddingFullBlock()
    {
        var padding = new ZerosPadding();
        byte[] input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        var result = padding.ApplyPadding(input, 8);
        TestsUtils.AssertEqualBlocks(result, input, nameof(TestZerosPaddingFullBlock));
    }
    
    public static void TestANSIPaddingApply()
    {
        var padding = new ANSIx923Padding();
        byte[] input = [0x01, 0x02, 0x03];
        
        var result = padding.ApplyPadding(input, 8);
        byte[] expected = [0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x05];
        TestsUtils.AssertEqualBlocks(result, expected, nameof(TestANSIPaddingApply));
    }
    
    public static void TestANSIPaddingRemove()
    {
        var padding = new ANSIx923Padding();
        byte[] input = [0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x05];
        
        var result = padding.RemovePadding(input, 8);
        byte[] expected = [0x01, 0x02, 0x03];
        TestsUtils.AssertEqualBlocks(result, expected, nameof(TestANSIPaddingRemove));
    }
    
    public static void TestANSIPaddingAllCycle()
    {
        var padding = new ANSIx923Padding();
        byte[] original = [0x01, 0x02, 0x03, 0x04, 0x05];
        var padded = padding.ApplyPadding(original, 8);
        var unpadded = padding.RemovePadding(padded, 8);
        TestsUtils.AssertEqualBlocks(original, unpadded, nameof(TestANSIPaddingAllCycle));
    }
    
    public static void TestANSIPaddingInvalidPadding()
    {
        var padding = new ANSIx923Padding();
        byte[] input = [0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x05];
        var result = padding.RemovePadding(input, 8);
        TestsUtils.AssertEqualBlocks(result, input,  nameof(TestANSIPaddingInvalidPadding));
    }
    
    public static void TestPKCS7PaddingApply()
    {
        var padding = new PKCS7Padding();
        byte[] input = [0x01, 0x02, 0x03];
        
        var result = padding.ApplyPadding(input, 8);
        byte[] expected = [0x01, 0x02, 0x03, 0x05, 0x05, 0x05, 0x05, 0x05];
        TestsUtils.AssertEqualBlocks(result, expected, nameof(TestPKCS7PaddingApply));
    }
    
    public static void TestPKCS7PaddingRemove()
    {
        var padding = new PKCS7Padding();
        byte[] input = [0x01, 0x02, 0x03, 0x05, 0x05, 0x05, 0x05, 0x05];
        
        var result = padding.RemovePadding(input, 8);
        byte[] expected = [0x01, 0x02, 0x03];
        TestsUtils.AssertEqualBlocks(result, expected, nameof(TestPKCS7PaddingRemove));
    }
    
    public static void TestPKCS7PaddingAllCycle()
    {
        var padding = new PKCS7Padding();
        byte[] original = [0x01, 0x02, 0x03, 0x04, 0x05];

        var padded = padding.ApplyPadding(original, 8);
        var unpadded = padding.RemovePadding(padded, 8);
        TestsUtils.AssertEqualBlocks(original, unpadded, nameof(TestPKCS7PaddingAllCycle));
    }
    
    public static void TestPKCS7PaddingFullBlock()
    {
        var padding = new PKCS7Padding();
        byte[] input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        
        var result = padding.ApplyPadding(input, 8);
        TestsUtils.AssertEqual((byte)result.Length, 16, nameof(TestPKCS7PaddingFullBlock) + "length");

        for (var i = 8; i < 16; i++)
        {
            TestsUtils.AssertEqual(result[i], 0x08, nameof(TestPKCS7PaddingFullBlock) + "byte" + i);
        }
    }
    
    public static void TestPKCS7PaddingInvalidPadding()
    {
        var padding = new PKCS7Padding();
        byte[] input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x04, 0x05];
        var result = padding.RemovePadding(input, 8);
        TestsUtils.AssertEqualBlocks(input, result,  nameof(TestPKCS7PaddingInvalidPadding));
    }
    
    public static void TestISOPaddingApply()
    {
        var padding = new ISO10126Padding();
        byte[] input = [0x01, 0x02, 0x03];
        var result = padding.ApplyPadding(input, 8);
        TestsUtils.AssertEqual((byte)result.Length, 8, nameof(TestISOPaddingApply) + "length");
        TestsUtils.AssertEqual(result[0], 0x01, nameof(TestISOPaddingApply) + "byte0");
        TestsUtils.AssertEqual(result[1], 0x02, nameof(TestISOPaddingApply) + "byte1");
        TestsUtils.AssertEqual(result[2], 0x03, nameof(TestISOPaddingApply) + "byte2");
        TestsUtils.AssertEqual(result[7], 0x05, nameof(TestISOPaddingApply) + "LastByte");
    }
    
    public static void TestISOPaddingRemove()
    {
        var padding = new ISO10126Padding();
        byte[] input = [0x01, 0x02, 0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0x05];
        
        var result = padding.RemovePadding(input, 8);
        byte[] expected = [0x01, 0x02, 0x03];
        TestsUtils.AssertEqualBlocks(result, expected, nameof(TestISOPaddingRemove));
    }
    
    
    public static void TestISOPaddingAllCycle()
    {
        var padding = new ISO10126Padding();
        byte[] input = [0x01, 0x02, 0x03, 0x04, 0x05];
        
        var padded =  padding.ApplyPadding(input, 8);
        var unpadded = padding.RemovePadding(padded, 8);
        TestsUtils.AssertEqualBlocks(input, unpadded, nameof(TestISOPaddingAllCycle));
    }
    
    
    public static void TestISOPaddingInvalidPadding()
    {
        var padding = new ISO10126Padding();
        byte[] input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00];
        var result = padding.RemovePadding(input, 8);
        TestsUtils.AssertEqualBlocks(input, result, nameof(TestISOPaddingInvalidPadding));
    }
}