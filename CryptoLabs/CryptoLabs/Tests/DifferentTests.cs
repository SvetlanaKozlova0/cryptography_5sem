namespace CryptoLabs.Tests;
using System.Numerics;
using CryptoLabs.Utility.MathUtils;
using CryptoLabs.RSA.AttacksOnRSA;

public class DifferentTests
{
    public static void TestSimplePermutation()
    {
        byte[] input = [ 0b11110000 ];
        uint[] permutation = [1, 5, 2, 6, 3, 7, 4, 8];
        
        byte[] result = BitFunctions.Permutation(input, permutation, false, false);
        
        TestsUtils.AssertEqual(result[0], 0b10101010, nameof(TestSimplePermutation));
    }
    
    
    public static void TestLittleEndian()
    {
        byte[] input = [0b11001100];
        uint[] permutation = [1, 2, 3, 4, 5, 6, 7, 8];
        
        byte[] result = BitFunctions.Permutation(input, permutation, true, false);
        
        TestsUtils.AssertEqual(result[0], 0b11001100, nameof(TestLittleEndian));
    }

    
    public static void TestFirstIndexIsNull()
    {
        byte[] input = [0b11110000];
        uint[] firstPermutation = [1, 5, 2, 6,  3, 7, 4, 8];
        uint[] secondPermutation = [0, 4, 1, 5, 2, 6, 3, 7];

        byte[] firstResult = BitFunctions.Permutation(input, firstPermutation, false, false);
        byte[] secondResult = BitFunctions.Permutation(input, secondPermutation, false, true);
        
        TestsUtils.AssertEqual(firstResult[0], secondResult[0], nameof(TestFirstIndexIsNull));
    }

    
    public static void TestMultiplyBytes()
    {
        byte[] input = [0x12, 0x34];
        uint[] permutation = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        byte[] result = BitFunctions.Permutation(input, permutation, false, false);
        
        TestsUtils.AssertEqual(result[0], 0x12, nameof(TestMultiplyBytes) + "byte1");
        TestsUtils.AssertEqual(result[1], 0x34, nameof(TestMultiplyBytes) + "byte2");
    }

    
    public static void TestEmptyPermutationBlock()
    {
        byte[] input = [ 0xFF ];
        uint[] permutation = [];
        
        bool exceptionThrown = false;
        try
        {
            BitFunctions.Permutation(input, permutation, false, false);
        }
        catch (ArgumentOutOfRangeException)
        {
            exceptionThrown = true; 
        }
        
        if (!exceptionThrown)
        {
            throw new Exception($"Test {nameof(TestEmptyPermutationBlock)} failed: Expected exception was not thrown");
        }
        Console.WriteLine($"✓ {nameof(TestEmptyPermutationBlock)}");
    }
    
    
    public static void TestWrongPermutationIndex()
    {
        byte[] input = [ 0xFF ];
        uint[] permutation = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        bool exceptionThrown = false;
        
        try
        {
            BitFunctions.Permutation(input, permutation, false, false);
        }
        catch (ArgumentOutOfRangeException)
        {
            exceptionThrown = true; 
        }
        
        if (!exceptionThrown)
        {
            throw new Exception($"Test {nameof(TestWrongPermutationIndex)} failed: Expected exception was not thrown");
        }
        
        Console.WriteLine($"✓ {nameof(TestWrongPermutationIndex)}");
    }

    
    public static void TestReversePermutation()
    {
        byte[] input = [0b00001111];
        uint[] permutation = [8, 7, 6, 5, 4, 3, 2, 1];

        byte[] result = BitFunctions.Permutation(input, permutation, false, false);
        TestsUtils.AssertEqual(result[0], 0b11110000,  nameof(TestReversePermutation));
    }
    
    
    public static void TestMultipleBytesBigEndian()
    {
        byte[] input = [ 0x12, 0x34, 0x56, 0x78 ];
        uint[] permutation = [
            25, 26, 27, 28, 29, 30, 31, 32,
            17, 18, 19, 20, 21, 22, 23, 24,
            9, 10, 11, 12, 13, 14, 15, 16,
            1, 2, 3, 4, 5, 6, 7, 8
        ];

        byte[] result = BitFunctions.Permutation(input, permutation, 
            littleEndian: false, firstIndexIsNull: false);

        TestsUtils.AssertEqual(result[0], 0x78, nameof(TestMultipleBytesBigEndian) + " byte1");
        TestsUtils.AssertEqual(result[1], 0x56, nameof(TestMultipleBytesBigEndian) + " byte2");
        TestsUtils.AssertEqual(result[2], 0x34, nameof(TestMultipleBytesBigEndian) + " byte3");
        TestsUtils.AssertEqual(result[3], 0x12, nameof(TestMultipleBytesBigEndian) + " byte4");
    }

    
    public static void TestCrossBytePermutation()
    {
        byte[] input = [ 0xAA, 0x55 ];
        uint[] permutation = [2, 4, 6, 8, 9, 11, 13, 15]; 
        
        byte[] result = BitFunctions.Permutation(input, permutation, 
            littleEndian: false, firstIndexIsNull: false);
        
        TestsUtils.AssertEqual(result[0], 0x0, nameof(TestCrossBytePermutation));
    }
    
    
    public static void TestDesInitialPermutation()
    {
        byte[] input = [
            0x01, 0x23, 0x45, 0x67, 
            0x89, 0xAB, 0xCD, 0xEF 
        ];
    
        uint[] ipTable = [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        ];
        
        byte[] result = BitFunctions.Permutation(input, ipTable, 
            littleEndian: false,  
            firstIndexIsNull: false); 

        byte[] expected = [
            0xCC, 0x00, 0xCC, 0xFF, 
            0xF0, 0xAA, 0xF0, 0xAA 
        ];

        for (int i = 0; i < expected.Length; i++)
        {
            if (result[i] != expected[i])
            {
                throw new Exception($"Test {nameof(TestDesInitialPermutation)} failed at byte {i}: " +
                                    $"Expected {expected[i]:X2}, got {result[i]:X2}");
            }
        }
    
        Console.WriteLine($"✓ {nameof(TestDesInitialPermutation)}");
        Console.WriteLine($"  Input:  {BitConverter.ToString(input).Replace("-", " ")}");
        Console.WriteLine($"  Output: {BitConverter.ToString(result).Replace("-", " ")}");
    }

    
    public static void BezoutTest1()
    {
        BigInteger a = 240;
        BigInteger b = 46;
        Utility.MathUtils.NumberTheoryFunctions.BezoutIdentity(a, b, out var s, out var t);
        var result = s * a + t * b;
        if (result == BigInteger.GreatestCommonDivisor(a, b))
        {
            Console.WriteLine("Right answer.");
        }
        else
        {
            Console.WriteLine("Wrong answer.");
        }
    }

    
    public static void BezoutTest2()
    {
        BigInteger a = 17;
        BigInteger b = 13;
        Utility.MathUtils.NumberTheoryFunctions.BezoutIdentity(a, b, out var s, out var t);
        var result = s * a + t * b;
        if (result == BigInteger.One)
        {
            Console.WriteLine("Right answer.");
        }
        else
        {
            Console.WriteLine("Wrong answer.");
        }
    }
    
    
    public static void BezoutTest3()
    {
        BigInteger a = 15;
        BigInteger b = 28;
        Utility.MathUtils.NumberTheoryFunctions.BezoutIdentity(a, b, out var s, out var t);
        var result = s * a + t * b;
        if (result == BigInteger.One)
        {
            Console.WriteLine("Right answer.");
        }
        else
        {
            Console.WriteLine("Wrong answer.");
        }
    }
    
    
    public static void BezoutTest4()
    {
        BigInteger a = 0;
        BigInteger b = 5;
        Utility.MathUtils.NumberTheoryFunctions.BezoutIdentity(a, b, out var s, out var t);
        var result = s * a + t * b;
        if (result == BigInteger.Abs(b))
        {
            Console.WriteLine("Right answer.");
        }
        else
        {
            Console.WriteLine("Wrong answer.");
        }
    }
    
    
    public static void BezoutTest5()
    {
        BigInteger a = 0;
        BigInteger b = 0;
        Utility.MathUtils.NumberTheoryFunctions.BezoutIdentity(a, b, out var s, out var t);
        var result = s * a + t * b;
        if (result == BigInteger.Zero)
        {
            Console.WriteLine("Right answer.");
        }
        else
        {
            Console.WriteLine("Wrong answer.");
        }
    }
    
    
    public static void TestWienerAttack()
    {
        BigInteger p = 10007;
        BigInteger q = 10009;

        var n = p * q;
        var phi = (p - 1) * (q - 1);

        BigInteger d = 29;

        if (NumberTheoryFunctions.EuclideanAlgorithm(d, phi) != 1)
            throw new Exception("Chosen d is not coprime with phi. Pick another d.");

        NumberTheoryFunctions.BezoutIdentity(d, phi, out var x, out _);
        var e = x % phi;
        
        if (e < 0)
        {
            e += phi;
        }

        Console.WriteLine($"p = {p}, q = {q}");
        Console.WriteLine($"n = {n}");
        Console.WriteLine($"phi = {phi}");
        Console.WriteLine($"d (real) = {d}");
        Console.WriteLine($"e = {e}");
        Console.WriteLine();

        var (recoveredD, recoveredPhi, steps) = WienerAttack.Attack(e, n);

        Console.WriteLine($"d (recovered) = {recoveredD}");
        Console.WriteLine($"phi (recovered) = {recoveredPhi}");
        Console.WriteLine($"steps number = {steps.Count}");
        Console.WriteLine();

        var dRecoveredRight = recoveredD == d;
        var phiRecoveredRight = recoveredPhi == phi;

        var result = ((e * recoveredD - 1) % recoveredPhi) == 0;
        
        Console.WriteLine($"d equal: {dRecoveredRight}");
        Console.WriteLine($"phi equal: {phiRecoveredRight}");
        Console.WriteLine($"(e * d - 1) % phi == 0 : {result}");
        Console.WriteLine();

        if (!dRecoveredRight || !phiRecoveredRight || !result)
        {
            throw new Exception("Wiener attack test failed.");
        }
        Console.WriteLine("Wiener attack successful.");
    }
}