namespace CryptoLabs.Utility.MathUtils;
using System.Numerics;

public class CustomRandomNumberGenerator
{
    readonly Random random = new();

    public BigInteger GenerateRandomBigInteger(long bitLength)
    {
        if (bitLength < 2)
        {
            throw new ArgumentException("Incorrect bit length, must be > 2, but got:", nameof(bitLength));
        }

        var byteCount = (bitLength + 7) / 8;
        var data = new byte[byteCount];
        
        random.NextBytes(data);
        
        data[0] |= 0x01;
        
        var lastBitIndex = bitLength - 1;
        var lastByteIndex = lastBitIndex / 8;
        var bitOffset = lastBitIndex % 8;
        
        data[lastByteIndex] |= (byte)(1 << (int)bitOffset);
        
        var bitsInLastByte = bitLength % 8;
        
        if (bitsInLastByte == 0)
        {
            bitsInLastByte = 8;
        }
        
        var mask = (byte)((1 << (int)bitsInLastByte) - 1);
        
        data[lastByteIndex] &= mask;
        
        return new BigInteger(data, isUnsigned: true);
    }
}