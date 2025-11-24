namespace CryptoLabs.Utility.MathUtils;
using GF = GaloisFieldArithmeticNoValidation;

public class PolynomialOverGF(byte a3, byte a2, byte a1, byte a0)
{
    public byte a3 = a3, a2 = a2, a1 = a1, a0 = a0;
    public static PolynomialOverGF Add(PolynomialOverGF a, PolynomialOverGF b)
    {
        return new PolynomialOverGF(
            GF.Add(a.a3, b.a3),
            GF.Add(a.a2, b.a2),
            GF.Add(a.a1, b.a1),
            GF.Add(a.a0, b.a0));
    }

    public static PolynomialOverGF Mult(PolynomialOverGF a, PolynomialOverGF b, byte mod)
    {
        var a3 = (byte)(GF.ModMult(a.a3, b.a0, mod) ^
                         GF.ModMult(a.a2, b.a1, mod) ^
                         GF.ModMult(a.a1, b.a2, mod) ^
                         GF.ModMult(a.a0, b.a3, mod));

        var a2 = (byte)(GF.ModMult(a.a2, b.a0, mod) ^
                         GF.ModMult(a.a1, b.a1, mod) ^
                         GF.ModMult(a.a0, b.a2, mod) ^
                         GF.ModMult(a.a3, b.a3, mod));

        var a1 = (byte)(GF.ModMult(a.a1, b.a0, mod) ^
                         GF.ModMult(a.a0, b.a1, mod) ^
                         GF.ModMult(a.a3, b.a2, mod) ^
                         GF.ModMult(a.a2, b.a3, mod));

        var a0 = (byte)(GF.ModMult(a.a0, b.a0, mod) ^
                         GF.ModMult(a.a3, b.a1, mod) ^
                         GF.ModMult(a.a2, b.a2, mod) ^
                         GF.ModMult(a.a1, b.a3, mod));
        
        return new PolynomialOverGF(a3, a2, a1, a0);
    }
    
    public static PolynomialOverGF operator +(PolynomialOverGF a, PolynomialOverGF b) 
        => Add(a, b);
    
}