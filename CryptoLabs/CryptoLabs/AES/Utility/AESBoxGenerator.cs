namespace CryptoLabs.AES.Utility;
using GF = CryptoLabs.Utility.MathUtils.GaloisFieldArithmeticNoValidation;

public class RijndaelBoxGenerator
{
    private const int BoxLength = 256;
    private const byte XorPoly = 0x63;
    public byte Polynomial { get; }
    private bool _wasGenerated;
    private byte[] _sBox;
    private byte[] _invBox;
    
    
    public RijndaelBoxGenerator(byte poly)
    {
        Polynomial = poly;
    }
    
    
    private (byte[] SBox, byte[] InvertedSBox) GenerateSBoxes()
    {
        var sBox = new byte[BoxLength];
        var invertedBox = new byte[BoxLength];

        for (var i = 0; i < BoxLength; i++)
        {
            var inverted = (i == 0) ? (byte) 0 : GF.InverseFermat((byte)i, Polynomial);
            var affine = AffineTransformation(inverted);
            var value = (byte)((affine ^ XorPoly) & 0xFF);
            sBox[i] = value;
            invertedBox[value & 0xFF] = (byte)i;
        }
        return (sBox, invertedBox);
    }


    public byte[] SBox()
    {
        if (_wasGenerated)
        {
            return _sBox;
        }
        (_sBox, _invBox) = GenerateSBoxes();
        _wasGenerated = true;
        return _sBox;
    }

    
    public byte[] InvSBox()
    {
        if (_wasGenerated)
        {
            return _invBox;
        }
        (_sBox, _invBox) = GenerateSBoxes();
        _wasGenerated = true;
        return _invBox;
    }

    
    private static byte ShiftLeftCycle(byte a, int shift)
    {
        int b = a & 0xFF;
        return (byte)(((b << shift) | (b >> (8 - shift))) & 0xFF);
    }

    
    private static byte AffineTransformation(byte b)
    {
        return (byte)(b ^
                      (ShiftLeftCycle(b, 4)) ^
                      (ShiftLeftCycle(b, 3)) ^ 
                      (ShiftLeftCycle(b, 2)) ^ 
                      (ShiftLeftCycle(b, 1))
            );
    }
}