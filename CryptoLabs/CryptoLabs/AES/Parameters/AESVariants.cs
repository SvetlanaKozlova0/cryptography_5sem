using CryptoLabs.Utility.MathUtils;

namespace CryptoLabs.AES.Parameters;

public class RijndaelSpecification
{
    public int Nk { get; } 
    public int Nb { get; }   
    public int Nr { get; }

    public RijndaelSpecification(int nk, int nb)
    {
        if (nk < 4 || nk > 8)
            throw new ArgumentException($"Nk must be 4..8, got {nk}.");

        if (nb != 4 && nb != 6 && nb != 8)
            throw new ArgumentException($"Nb must be 4, 6 or 8, got {nb}.");

        Nk = nk;
        Nb = nb;
        Nr = Math.Max(Nk, Nb) + 6;
    }

    public RijndaelSpecification(int nk) : this(nk, 4) { }
}


class RijndaelPoly
{
    public readonly PolynomialOverGF MixColumnsPoly = new (0x03, 0x01, 0x01, 0x02); 
    public readonly PolynomialOverGF InvMixColumnsPoly = new (0x0b, 0x0d, 0x09, 0x0e);
}