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
        if (data.Length % BlockSize != 0)
        {
            throw new ArgumentException("Data must be multiple of BlockSize");
        }
        if (iv.Length != BlockSize)
        {
            throw new ArgumentException($"IV must be {BlockSize} bytes");
        }
        byte[] resultData = new byte[data.Length];
        byte[] plainText = new byte[BlockSize];
        Array.Copy(iv, plainText, BlockSize);
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] encryptedPlainText = cipher.Encrypt(plainText);
            byte[] currentBlock = new byte[BlockSize];
            Array.Copy(data, i, currentBlock, 0, BlockSize);
            byte[] encrypted = BitFunctions.XorBlocks(currentBlock, encryptedPlainText, BlockSize);
            Array.Copy(encrypted, 0, resultData, i, BlockSize);
            Array.Copy(encrypted, plainText, BlockSize);
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
        byte[] plainText = new byte[BlockSize];
        Array.Copy(iv, plainText, BlockSize);
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] encryptedPlainText = cipher.Encrypt(plainText);
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);
            byte[] decrypted = BitFunctions.XorBlocks(current, encryptedPlainText, BlockSize);
            Array.Copy(decrypted, 0, resultData, i, BlockSize);
            Array.Copy(current, plainText, BlockSize);
        }

        return resultData;
    }
    public CipherMode Mode => CipherMode.CFB;
    public int BlockSize => 8;
}

public class OFBMode : ICipherMode
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
        byte[] plainText = new byte[BlockSize];
        Array.Copy(iv, plainText, BlockSize);
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] encryptedPlainText = cipher.Encrypt(plainText);
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);
            byte[] xored = BitFunctions.XorBlocks(current, encryptedPlainText, BlockSize);
            Array.Copy(xored, 0, resultData, i, BlockSize);
            Array.Copy(encryptedPlainText, plainText, BlockSize);
        }

        return resultData;
    }

    public byte[] Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        return Encrypt(cipher, data, iv);
    }
    public CipherMode Mode => CipherMode.OFB;
    public int BlockSize => 8;
}

public class CTRMode : ICipherMode
{
    private void IncrementCounter(byte[] counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }
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
        byte[] counter = new byte[BlockSize];
        Array.Copy(iv, counter, BlockSize);

        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] encryptedPlainText = cipher.Encrypt(counter);
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);

            byte[] xored = BitFunctions.XorBlocks(current, encryptedPlainText, BlockSize);
            Array.Copy(xored, 0, resultData, i, BlockSize);
            IncrementCounter(counter);
        }

        return resultData;
    }

    
    public byte[] Decrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        return Encrypt(cipher, data, iv);
    }
    public CipherMode Mode => CipherMode.CTR;
    public int BlockSize => 8;
}

//need to think about design to keep deltas
public class RandomDeltaMode : ICipherMode
{
    private readonly Random _random = new Random();
    public List<byte[]> Deltas { get; } = new List<byte[]>();
    public byte[] Encrypt(ISymmetricCipher cipher, byte[] data, byte[] iv)
    {
        if (data.Length % BlockSize != 0)
        {
            throw new ArgumentException("Data must be multiple of BlockSize");
        }
        byte[] resultData = new byte[data.Length];
        Deltas.Clear();
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);
            byte[] newDelta = new byte[BlockSize];
            _random.NextBytes(newDelta);
            Deltas.Add(newDelta);
            byte[] xored = BitFunctions.XorBlocks(current, newDelta, BlockSize);
            byte[] encrypted = cipher.Encrypt(xored);
            Array.Copy(encrypted, 0, resultData, i, BlockSize);
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
        for (int i = 0; i < data.Length; i += BlockSize)
        {
            byte[] current = new byte[BlockSize];
            Array.Copy(data, i, current, 0, BlockSize);
            byte[] decrypted = cipher.Decrypt(current);
            byte[] delta = Deltas[i / BlockSize];
            byte[] original = BitFunctions.XorBlocks(decrypted, delta, BlockSize);
            Array.Copy(original, 0, resultData, i, BlockSize);
        }

        return resultData;
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

