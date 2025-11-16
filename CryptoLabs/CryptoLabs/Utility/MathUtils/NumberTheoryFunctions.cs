namespace CryptoLabs.Utility.MathUtils;
using System.Numerics;
public class NumberTheoryFunctions
{
    public static int LegendreSymbol(BigInteger a, BigInteger p)
    {
        if (p <= 2 || p % 2 == 0)
        {
            throw new ArgumentException("p must be an odd prime > 2");
        }
        
        a = (a % p + p) % p;
        
        if (a == 0)
        {
            return 0;
        }
        
        return ModPow(a, (p - 1) / 2, p) == 1 ? 1 : -1;
    }

    public static int JacobiSymbol(BigInteger a, BigInteger b)
    {
        if (b <= 0 || b % 2 == 0)
        {
            throw new ArgumentException("b must be a positive odd integer");
        }

        if (b == 1)
        {
            return 1;
        }
        
        a %= b;
        
        if (a < 0)
        {
            a += b;
        }
        
        if (a == 0)
        {
            return 0;
        }
        
        int r = 1;
        
        while (a != 0)
        {
            int t = 0;
            while (a % 2 == 0)
            {
                t++; 
                a /= 2;
            }
            if (t % 2 == 1 && (b % 8 == 3 || b % 8 == 5))
            {
                r = -r;
            }
            if (a % 4 == 3 && b % 4 == 3)
            {
                r = -r;
            }
            (a, b) = (b % a, a);
        }
        return b == 1 ? r : 0;
    }
    
    public static BigInteger EuclideanAlgorithm(BigInteger a, BigInteger b)
    {
        a = a >= 0 ? a : -a;
        b = b >= 0 ? b : -b;
        while (b != 0)
        {
            (b, a) = (a % b, b);
        }
        return a;
    }

    public static void BezoutIdentity(BigInteger a, BigInteger b, out BigInteger coefficientS, out BigInteger coefficientT)
    {
        BigInteger prevR = a, r = b;
        BigInteger prevS = 1, s = 0;
        BigInteger prevT = 0, t = 1;
        
        while (r != 0)
        {
            BigInteger quotient = prevR / r;
            (prevR, r) = (r, prevR - quotient * r);
            (prevS, s) = (s, prevS - quotient * s);
            (prevT, t) = (t, prevT - quotient * t);
        }
        
        coefficientS = prevS;
        coefficientT = prevT;
    }

    public static BigInteger ModPow(BigInteger number, BigInteger exp, BigInteger modulus)
    {
        if (modulus <= 0)
        {
            throw new  ArgumentException("modulus must be greater than 0");
        }
        if (exp < 0)
        {
            throw new ArgumentException("exp must be greater than 0");
        }
        
        BigInteger result = 1;
        
        while (exp > 0)
        {
            if ((exp & 1) == 1)
            {
                result = (result * number) % modulus;
            }
            exp >>= 1;
            number = (number * number) % modulus;
        }
        
        return result;
    }
}