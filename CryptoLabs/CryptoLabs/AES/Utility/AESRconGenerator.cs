namespace CryptoLabs.AES.Utility;
using GF = CryptoLabs.Utility.MathUtils.GaloisFieldArithmetic;

public class AESRconGenerator(in int nb, in int nr, in byte polynomial)
{
    private readonly int _nb = nb;
    private readonly int _nr = nr;
    private readonly byte _poly = polynomial;
    private byte[][] rconCache;
    private bool _generated = false;
    
    public byte[][] GenerateRCon()
    {
        if (_generated)
        {
            return rconCache;
        }
        var size = 4 * _nb * (_nr + 1);
        var result = new byte[size][];
        result[0] = new byte[4];
        result[1] = new byte[4];
        result[1][0] = 1;

        for (int i = 2; i < size; i++)
        {
            byte previous = result[i - 1][0];
            byte next = GF.OneMult(previous, _poly);
            result[i] = new byte[4];
            result[i][0] = next;
        }

        _generated = true;
        rconCache = result;
        return result;
    }
}