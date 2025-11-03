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
    byte[] Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv);
    CipherMode Mode { get; }
    int BlockSize { get; }
}

public class ECBMode : ICipherMode
{
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        if (data.Length % BlockSize != 0)
        {
            throw new ArgumentException("Data must be multiple of BlockSize");
        }
        byte[] resultData = new byte[data.Length];
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);
            byte[] encrypted = cipher.Encrypt(current);
            Array.Copy(encrypted, 0, resultData, i, BlockSize);
        }
        return resultData;
    }

    public byte[] Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        byte[] resultData = new byte[data.Length];
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);
            byte[] decrypted = cipher.Decrypt(current);
            Array.Copy(decrypted, 0, resultData, i, BlockSize);
        }
        return resultData;
    }
    public CipherMode Mode => CipherMode.ECB;
    public int BlockSize => 8;
}

public class CBCMode : ICipherMode
{
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        if (data.Length % BlockSize != 0)
        {
            throw new ArgumentException("Data must be multiple of BlockSize");
        }
        byte[] resultData = new byte[data.Length];
        byte[] previous = new byte[BlockSize];
        Array.Copy(iv, previous, BlockSize);
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);
            byte[] xored = BitFunctions.XorBlocks(current, previous, BlockSize);
            byte[] encrypted = cipher.Encrypt(xored);
            Array.Copy(encrypted, 0, resultData, i, BlockSize);
            Array.Copy(encrypted, previous, BlockSize);
        }
        return resultData;
    }

    public byte[] Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        if (data.Length % BlockSize != 0)
        {
            throw new ArgumentException("Data must be multiple of BlockSize");
        }
        byte[] resultData = new byte[data.Length];
        byte[] previous = new byte[BlockSize];
        Array.Copy(iv, previous, BlockSize);
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);
            byte[] decrypted = cipher.Decrypt(current);
            byte[] xored = BitFunctions.XorBlocks(decrypted, previous, BlockSize);
            Array.Copy(xored, 0, resultData, i, BlockSize);
            Array.Copy(current, previous, BlockSize);
        }
        return resultData;
    }
    public CipherMode Mode => CipherMode.CBC;
    public int BlockSize => 8;
}

public class PCBCMode : ICipherMode
{
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        if (data.Length % BlockSize != 0)
        {
            throw new ArgumentException("Data must be multiple of BlockSize");
        }
        if (iv.Length != BlockSize)
        {
            throw new ArgumentException($"IV must be {BlockSize} bytes");
        }
        
        byte[] resultData = new byte[data.Length];
        byte[] previousStart = new byte[BlockSize];
        Array.Copy(iv, previousStart, BlockSize);
        byte[] previousEnd = new byte[BlockSize];
        Array.Copy(iv, previousEnd, BlockSize);
        
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);
            byte[] xored = BitFunctions.XorBlocks(current,
                    BitFunctions.XorBlocks(previousStart, previousEnd, BlockSize), BlockSize);
            byte[] encrypted = cipher.Encrypt(xored);
            Array.Copy(encrypted, 0, resultData, i, BlockSize);
            Array.Copy(current, previousStart, BlockSize);    
            Array.Copy(encrypted, previousEnd, BlockSize);    
        }
        return resultData;
    }

    public byte[] Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        if (data.Length % BlockSize != 0)
        {
            throw new ArgumentException("Data must be multiple of BlockSize");
        }
        if (iv.Length != BlockSize)
        {
            throw new ArgumentException($"IV must be {BlockSize} bytes");
        }
        byte[] resultData = new byte[data.Length];
        byte[] previousStart = new byte[BlockSize];
        Array.Copy(iv, previousStart, BlockSize);
        byte[] previousEnd = new byte[BlockSize];
        Array.Copy(iv, previousEnd, BlockSize);
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);
            byte[] decrypted = cipher.Decrypt(current);
            byte[] xored = BitFunctions.XorBlocks(decrypted, 
                BitFunctions.XorBlocks(previousStart, previousEnd, BlockSize), BlockSize);
            Array.Copy(xored, 0, resultData, i, BlockSize);
            Array.Copy(current, previousStart, BlockSize);
            Array.Copy(decrypted, previousEnd, BlockSize);
        }
        return resultData;
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

    public byte[] Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
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

    public byte[] Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
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

    public byte[] Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
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

    public byte[] Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
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

