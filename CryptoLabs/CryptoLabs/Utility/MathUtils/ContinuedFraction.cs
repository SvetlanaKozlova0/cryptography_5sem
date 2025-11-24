namespace CryptoLabs.Utility.MathUtils;
using System.Numerics;

public static class ContinuedFraction
{
    public static List<BigInteger> CoefficientsByGcd(BigInteger a, BigInteger b)
    {
        List<BigInteger> coefficients = [];
        while (b != 0)
        {
            var c = a / b;
            coefficients.Add(c);
            (a, b) = (b, a % b);
        }

        return coefficients;
    }

    
    public static (BigInteger, BigInteger) ToRegularFraction(List<BigInteger> coefficients)
    {
        var numerator = coefficients[^1];
        var denominator = BigInteger.One;
        var reversedCoefficients = coefficients.Reverse<BigInteger>().Skip(1);

        foreach (var coefficient in reversedCoefficients)
        {
            (numerator, denominator) = (denominator, numerator);
            numerator += (coefficient * denominator);
        }

        return (numerator, denominator);
    }
}