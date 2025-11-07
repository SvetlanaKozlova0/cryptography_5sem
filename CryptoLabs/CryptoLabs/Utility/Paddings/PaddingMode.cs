namespace CryptoLabs.Utility.Paddings;

public enum PaddingMode
{
    Zeros,
    ANSI_X923,
    PKCS7, 
    ISO10126
}

public interface IPadding
{
    public byte[] ApplyPadding(byte[] block, int blockSize);
    public byte[] RemovePadding(byte[] block, int blockSize);
    PaddingMode Mode { get; }
}

public class ZerosPadding : IPadding
{
    public byte[] ApplyPadding(byte[] block, int blockSize)
    {
        if (blockSize < 0 || blockSize > 256)
        {
            throw new ArgumentException($"Size of block must be between 0 and 256, but got {blockSize}");
        }
        if (block.Length % blockSize == 0)
        {
            return block;
        }

        int bytesToAdd = blockSize - (block.Length % blockSize);
        byte[] result = new byte[block.Length + bytesToAdd];
        Array.Copy(block, result, block.Length);
        return result;
    }

    public byte[] RemovePadding(byte[] block, int blockSize)
    {
        if (blockSize < 0 || blockSize > 256)
        {
            throw new ArgumentException($"Size of block must be between 0 and 256, but got {blockSize}");
        }
        if (block.Length == 0)
        {
            return block;
        }

        int lastNonZero = -1;
        for (int i = block.Length - 1; i >= 0; i--)
        {
            if (block[i] != 0)
            {
                lastNonZero = i;
                break;
            }
        }

        if (lastNonZero == -1)
        {
            return new byte[0];
        }

        byte[] result = new byte[lastNonZero + 1];
        Array.Copy(block, result, result.Length);
        return result;
    }
    public PaddingMode Mode => PaddingMode.Zeros;
}

public class ANSIx923Padding : IPadding
{
    public byte[] ApplyPadding(byte[] block, int blockSize)
    {
        if (blockSize < 0 || blockSize > 256)
        {
            throw new ArgumentException($"Size of block must be between 0 and 256, but got {blockSize}");
        }
        int bytesToAdd = blockSize - (block.Length % blockSize);
        if (bytesToAdd == 0)
        {
            bytesToAdd = blockSize;
        }
        byte[] result = new byte[block.Length + bytesToAdd];
        Array.Copy(block, result, block.Length);
        result[result.Length - 1] = (byte)bytesToAdd;
        return result;
    }

    public byte[] RemovePadding(byte[] block, int blockSize)
    {
        if (blockSize < 0 || blockSize > 256)
        {
            throw new ArgumentException($"Size of block must be between 0 and 256, but got {blockSize}");
        }
        if (block.Length == 0)
        {
            return block;
        }

        byte paddingSize = block[block.Length - 1];
        if (paddingSize == 0 || paddingSize > blockSize || paddingSize > block.Length)
        {
            throw new ArgumentException($"Invalid padding size: {paddingSize}");
        }

        for (int i = block.Length - paddingSize; i < block.Length - 1; i++)
        {
            if (block[i] != 0)
            {
                throw new ArgumentException("Non-zero byte found in ANSI X9.23 padding");
            }
        }

        byte[] result = new byte[block.Length - paddingSize];
        Array.Copy(block, result, result.Length);
        return result;
    }
    public PaddingMode Mode => PaddingMode.ANSI_X923;
}

public class PKCS7Padding : IPadding
{
    public byte[] ApplyPadding(byte[] block, int blockSize)
    {
        if (blockSize < 0 || blockSize > 256)
        {
            throw new ArgumentException($"Size of block must be between 0 and 256, but got {blockSize}");
        }
        int bytesToAdd = blockSize - (block.Length % blockSize);
        if (bytesToAdd == 0)
        {
            bytesToAdd = blockSize;
        }

        if (bytesToAdd > 256)
        {
            throw new ArgumentException($"To large bytes to add: {bytesToAdd}");
        }
        byte[] result = new byte[block.Length + bytesToAdd];
        Array.Copy(block, result, block.Length);
        for (int i = block.Length; i < result.Length; i++)
        {
            result[i] = (byte)bytesToAdd;
        }

        return result;
    }

    public byte[] RemovePadding(byte[] block, int blockSize)
    {
        if (blockSize < 0 || blockSize > 256)
        {
            throw new ArgumentException($"Size of block must be between 0 and 256, but got {blockSize}");
        }
        if (block.Length == 0)
        {
            return block;
        }
        byte paddingSize = block[block.Length - 1];
        if (paddingSize == 0 || paddingSize > blockSize || paddingSize > block.Length)
        {
            throw new ArgumentException($"Invalid padding size: {paddingSize}");
        }

        for (int i = block.Length - paddingSize; i < block.Length; i++)
        {
            if (block[i] != paddingSize)
            {
                throw new ArgumentException($"Invalid data: got {block[i]}, expected {paddingSize}");
            }
        }
        byte[] result = new byte[block.Length - paddingSize];
        Array.Copy(block, result, result.Length);
        return result;
    }
    public PaddingMode Mode => PaddingMode.PKCS7;
}

public class ISO10126Padding : IPadding
{
    private readonly Random _random = new Random();
    public byte[] ApplyPadding(byte[] block, int blockSize)
    {
        if (blockSize < 0 || blockSize > 256)
        {
            throw new ArgumentException($"Size of block must be between 0 and 256, but got {blockSize}");
        }
        int bytesToAdd = blockSize - (block.Length % blockSize);
        if (bytesToAdd == 0)
        {
            bytesToAdd = blockSize;
        }

        if (bytesToAdd > 256)
        {
            throw new ArgumentException($"Too large bytes to add: {bytesToAdd}");
        }
        byte[] result = new byte[block.Length + bytesToAdd];
        Array.Copy(block, result, block.Length);
        for (int i = block.Length; i < result.Length - 1; i++)
        {
            result[i] = (byte)_random.Next(256);
        }
        result[result.Length - 1] = (byte)bytesToAdd;
        return result;
    }

    public byte[] RemovePadding(byte[] block, int blockSize)
    {
        if (blockSize < 0 || blockSize > 256)
        {
            throw new ArgumentException($"Size of block must be between 0 and 256, but got {blockSize}");
        }
        if (block.Length == 0)
        {
            return block;
        }

        byte paddingSize = block[block.Length - 1];
        if (paddingSize < 1 || paddingSize > blockSize)
        {
            throw new ArgumentException($"Invalid padding size: {paddingSize}");
        }

        byte[] result = new byte[block.Length - paddingSize];
        Array.Copy(block, result, result.Length);
        return result;
    }
    public PaddingMode Mode => PaddingMode.ISO10126;
}

public static class PaddingFactory
{
    public static IPadding Create(PaddingMode mode)
    {
        return mode switch
        {
            PaddingMode.Zeros => new ZerosPadding(),
            PaddingMode.ANSI_X923 => new ANSIx923Padding(),
            PaddingMode.PKCS7 => new PKCS7Padding(),
            PaddingMode.ISO10126 => new ISO10126Padding(),
            _ => throw new ArgumentException($"Unsupported padding mode: {mode}", nameof(mode))
        };
    }
}
