using CryptoLabs.Utility.MathUtils;

namespace CryptoLabs.AES.Parameters;

public enum AESVariants
{
    AES_128,
    AES_192,
    AES_256
}

public class AESSpecification
{
    public int Nk { get; }
    public int Nb { get; }
    public int Nr { get; }

    public AESSpecification(int nk)
    {
        (Nk, Nb, Nr) = nk switch
        {
            4 => (4, 4, 10),
            6 => (6, 4, 12),
            8 => (8, 4, 14),
            _ => throw new ArgumentException($"Invalid key length. " +
                                             $"Must be 128 / 192 / 256 bytes, but got {nk * 32} bits.")
        };
    }
}


class AESPoly
{
    public readonly PolynomialOverGF MixColumnsPoly = new (0x03, 0x01, 0x01, 0x02); 
    public readonly PolynomialOverGF InvMixColumnsPoly = new (0x0b, 0x0d, 0x09, 0x0e);
}