using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.Utility.CipherModes;

public enum CipherMode
{
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR, 
    RandomDelta
}

public interface ICipherMode
{
    byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv);
    byte Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv);
    CipherMode Mode { get; }
    int BlockSize { get; }
}

public class ECBMode : ICipherMode
{
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }

    public byte Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }
    public CipherMode Mode => CipherMode.ECB;
    public int BlockSize => 8;
}

public class CBCMode : ICipherMode
{
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }

    public byte Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }
    public CipherMode Mode => CipherMode.CBC;
    public int BlockSize => 8;
}

public class PCBCMode : ICipherMode
{
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }

    public byte Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }
    public CipherMode Mode => CipherMode.PCBC;
    public int BlockSize => 8;
}

public class CFBMode : ICipherMode
{
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }

    public byte Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }
    public CipherMode Mode => CipherMode.CFB;
    public int BlockSize => 8;
}

public class OFBMode : ICipherMode
{
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }

    public byte Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }
    public CipherMode Mode => CipherMode.OFB;
    public int BlockSize => 8;
}

public class CTRMode : ICipherMode
{
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }

    public byte Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }
    public CipherMode Mode => CipherMode.CTR;
    public int BlockSize => 8;
}

public class RandomDeltaMode : ICipherMode
{
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }

    public byte Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        throw new NotImplementedException();
    }
    public CipherMode Mode => CipherMode.RandomDelta;
    public int BlockSize => 8;
}

public static class CipherModeFactory
{
    public static ICipherMode Create(CipherMode mode)
    {
        return mode switch
        {
            CipherMode.ECB => new ECBMode(),
            CipherMode.CBC => new CBCMode(),
            CipherMode.PCBC => new PCBCMode(),
            CipherMode.CFB => new CFBMode(),
            CipherMode.OFB => new OFBMode(),
            CipherMode.CTR => new CTRMode(),
            CipherMode.RandomDelta => new RandomDeltaMode()
        };
    }
}

