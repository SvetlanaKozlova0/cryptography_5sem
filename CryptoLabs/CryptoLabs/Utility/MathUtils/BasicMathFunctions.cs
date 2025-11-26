namespace CryptoLabs.Utility.MathUtils;
using System.Numerics;

public static class BasicMathFunctions
{
    private static BigInteger IntegerSqrt(BigInteger number)
    {
        if (number < 0)
        {
            throw new ArgumentException($"Negative values don't have a real quadratic root.");
        }

        if (number == 0 || number == 1)
        {
            return number;
        }

        var a = number;
        var b = (a + 1) / 2;
        
        while (b < a)
        {
            (a, b) = (b, (a + number / a) / 2);
        }

        return a;
    }
    
    
    public static (BigInteger? x1, BigInteger? x2) SolveQuadraticEquation(BigInteger a, BigInteger b, BigInteger c)
    {
        var discriminant = b * b - 4 * a * c;
        
        if (discriminant < 0)
        {
            return (null, null);
        }

        var x = IntegerSqrt(discriminant);
        
        if (x * x != discriminant)
        {
            return (null, null);
        }

        var x1 = (b - x) / (2 * a);
        var x2 = (b + x) / (2 * a);

        return (x1, x2);
    }
}