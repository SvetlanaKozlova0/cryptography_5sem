namespace CryptoLabs.Magenta.Utility;
using GF = CryptoLabs.Utility.MathUtils.GaloisFieldArithmeticNoValidation;

public class MagentaBoxGenerator
{
    private const int BoxLength = 256;
    private byte[] _sBox;
    private bool _wasGenerated;
    private byte Polynomial { get; }

    
    public MagentaBoxGenerator(byte poly)
    {
        Polynomial = poly;
    }

    
    private byte[] GenerateSBox()
    {
        var sBox = new byte[BoxLength];
        sBox[0] = 0x01;

        for (var i = 1; i < BoxLength; i++)
        {
            sBox[i] = GF.OneMult(sBox[i - 1], Polynomial);
        }

        sBox[^1] = 0x00;

        return sBox;
    }
    
    
    public byte[] SBox()
    {
        if (_wasGenerated)
        {
            return _sBox;
        }
        _sBox = GenerateSBox();
        _wasGenerated = true;
        return _sBox;
    }
}