namespace CryptoLabs.Utility.MathUtils;

public static class GaloisFieldArithmetic
{ 
    private static readonly byte[] IrreduciblePolynomialsCache = AllIrreducible8();
    
    public static byte Add(byte a, byte b)
    {
        return (byte)(a ^ b);
    }

    
    public static byte OneMult(byte a, byte mod)
    {
        return IsIrreducible(mod) 
            ? GaloisFieldArithmeticNoValidation.OneMult(a, mod)
            : throw new ArgumentException($"Can't use reducible polynomial as mod in OneMult.");
    }

    
    public static byte ModMult(byte a, byte b, byte mod)
    {
        return IsIrreducible(mod)
            ? GaloisFieldArithmeticNoValidation.ModMult(a, b, mod)
            : throw new ArgumentException($"Can't use reducible polynomial as mod in ModMult.");
    }

    
    public static byte ModPow(byte a, int degree, byte mod)
    {
        return IsIrreducible(mod)
            ? GaloisFieldArithmeticNoValidation.ModPow(a, degree, mod)
            : throw new ArgumentException($"Can't use reducible polynomial as mod in ModPow.");
    }

    
    public static byte InverseFermat(byte a, byte mod)
    {
        return IsIrreducible(mod)
            ? GaloisFieldArithmeticNoValidation.InverseFermat(a, mod)
            : throw new ArgumentException($"Can't use reducible polynomial as mod in InverseFermat.");
    }

    
    private static short Mult(short a, short b)
    {
        return GaloisFieldArithmeticNoValidation.Mult(a, b);
    }

    
    public static int Degree(short a)
    {
        return GaloisFieldArithmeticNoValidation.Degree(a);
    }

    
    private static void DivMod(short a, short b, out short result, out short modulo)
    {
        GaloisFieldArithmeticNoValidation.DivMod(a, b, out result, out modulo);
    }

    
    static short Div(short a, short b)
    {
        GaloisFieldArithmeticNoValidation.DivMod(a, b, out var result, out _);
        return result;
    }

    
    static short Mod(short a, short b)
    {
        GaloisFieldArithmeticNoValidation.DivMod(a, b, out var _, out var modulo);
        return modulo;
    }

    
    static bool IsIrreducible(short a, int degree)
    {
        return GaloisFieldArithmeticNoValidation.IsIrreducible(a, degree);
    }

    
    static List<short> AllIrreducible(int degree)
    {
        return GaloisFieldArithmeticNoValidation.AllIrreducible(degree);
    }

    
    public static byte[] AllIrreducible8()
    {
        return GaloisFieldArithmeticNoValidation.AllIrreducible8();
    }

    
    public static bool IsIrreducible(byte a)
    {
        return IrreduciblePolynomialsCache.Contains(a);
    }

    
    public static List<short> Factorize(short a)
    {
        return GaloisFieldArithmeticNoValidation.Factorize(a);
    }
}


public static class GaloisFieldArithmeticNoValidation
{
    private const byte MaskOldest = 0x80;
    private const byte MaskYoungest = 0x01;
    private const int ByteLength = 8;

    public static byte Add(byte a, byte b)
    {
        return (byte)(a ^ b);
    }
    
    
    public static byte OneMult(byte a, byte mod)
    {
        if ((a & MaskOldest) == MaskOldest)
        {
            return (byte)((a << 1) ^ mod);
        }

        return (byte)(a << 1);
    }
    
    
    public static byte ModMult(byte a, byte b, byte mod)
    {
        byte result = 0;
        for (var i = 0; i < ByteLength; i++)
        {
            if ((b & MaskYoungest) == MaskYoungest)
            {
                result ^= a;
            }

            a = OneMult(a, mod);
            b >>= 1;
        }

        return result;
    }
    
    
    public static byte ModPow(byte a, int degree, byte mod)
    {
        if (degree < 0)
        {
            throw new ArgumentException($"ModPow can operate only with positive and null degrees, but got {degree}.");
        }

        if (degree == 0)
        {
            return 1;
        }

        if (a == 0)
        {
            return 0;
        }

        if (degree == 1)
        {
            return a;
        }

        byte result = 1;
        while (degree > 0)
        {
            if ((degree & 1) == 1)
            {
                result = ModMult(result, a, mod);
            }

            a = ModMult(a, a, mod);
            degree >>= 1;
        }

        return result;
    }
    
    
    public static byte InverseFermat(byte a, byte mod)
    {
        return (a != 0) 
            ? ModPow(a, 254, mod)
            : throw new ArgumentException($"Can't find inverse element for 0.");
    }
    
    
    public static short Mult(short a, short b)
    {
        short result = 0;
        for (var i = 0; i < 16; i++)
        {
            if ((b & 1) != 0)
            {
                result ^= a;
            }

            a <<= 1;
            b >>= 1;
        }

        return result;
    }

    
    public static int Degree(short a)
    {
        if (a == 0)
        {
            return -1;
        }

        var degree = 0; 
        var temp = a & 0xFF;
        while (temp != 0)
        {
            degree++;
            temp >>= 1;
        }

        return degree;
    }
    
    
    public static void DivMod(short a, short b, out short result, out short modulo)
    {
        if (b == 0)
        {
            throw new ArgumentException($"Division by zero.");
        }

        var degreeB = Degree(b);
        result = 0;
        modulo = a;
        while (Degree(a) >= degreeB)
        {
            var offset = Degree(modulo) - degreeB;
            result ^= (short)(1 << offset);
            modulo ^= (short)(b << offset);
        }
    }
    
    
    public static short Div(short a, short b)
    {
        DivMod(a, b,  out var result, out var _);
        return result;
    }

    
    public static short Mod(short a, short b)
    {
        DivMod(a, b, out var _, out var modulo);
        return modulo;
    }
    
    
    public static bool IsIrreducible(short a, int degree)
    {
        var maxValue = 1 << (degree / 2 + 1);
        for (var i = 2; i < maxValue; i++)
        {
            if (Mod(a, (short)(i)) == 0)
            {
                return false;
            }
        }

        return true;
    }

    
    public static List<short> AllIrreducible(int degree)
    {
        var result = new List<short>();
        var first = (short)(1 << degree);
        var last = (short)(first << 1);
        for (var i = first; i < last; ++i)
        {
            if (IsIrreducible(i, degree))
            {
                result.Add(i);
            }
        }

        return result;
    }

    
    public static byte[] AllIrreducible8()
    {
        var allPolynomials = AllIrreducible(8);
        var result = new List<byte>();
        foreach (var poly in allPolynomials)
        {
            result.Add((byte)(poly & 0xff));
        }

        return result.ToArray();
    }
    
    
    public static List<short> Factorize(short a)
    {
        var factors = new List<short>();
        if (a == 0)
        {
            return factors;
        }

        var degree = Degree(a);
        if (degree == 0)
        {
            factors.Add(1);
            return factors;
        }

        if (IsIrreducible(a, degree))
        {
            factors.Add(a);
            return factors;
        }

        var maybeFactors = new List<short>();
        for (var i = 1; i < degree / 2; i++)
        {
            maybeFactors.AddRange(AllIrreducible(i));
        }

        foreach (var f in maybeFactors)
        {
            while (Mod(a, f) == 0)
            {
                factors.Add(f);
                a = Div(a, f);
                degree = Degree(a);
                if (a == 1)
                {
                    return factors;
                }

                if (!IsIrreducible(a, degree))
                {
                    continue;
                }

                factors.Add(a);
                return factors;
                
            }
        }
        if (a != 1)
        {
            factors.Add(a);
        }
        return factors;
    }
}