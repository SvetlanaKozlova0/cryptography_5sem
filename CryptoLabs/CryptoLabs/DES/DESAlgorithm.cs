namespace CryptoLabs.DES;
using CryptoLabs.Utility.Interfaces;

public class DESAlgorithm(byte[][] roundKeys): ISymmetricCipher
{
    private static readonly uint[] InitialPermutation =
    [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ];

    private static readonly uint[] InverseInitialPermutation =
    [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ];
    private byte[][] _roundKeys = roundKeys;
    private readonly IEncryptionRound _feistelNetwork = new FeistelNetwork();

    public int GetBlockSize()
    {
        return 8;
    }
    
    public byte[] Encrypt(byte[] inputBlock)
    {
        ValidateInputBlock(inputBlock);
        byte[] block = BitFunctions.Permutation(inputBlock, InitialPermutation, false, false);

        for (int i = 0; i < 16; i++)
        {
            block = _feistelNetwork.PerformEncryptConversion(block, _roundKeys[i]);
        }
        int halfSize = block.Length / 2;
        byte[] output = new byte[block.Length];
        Array.Copy(block, halfSize, output, 0, halfSize);
        Array.Copy(block, 0, output, halfSize, halfSize);
        return BitFunctions.Permutation(output, InverseInitialPermutation, false, false);
    }

    public byte[] Decrypt(byte[] inputBlock)
    {
        ValidateInputBlock(inputBlock);
        byte[] block = BitFunctions.Permutation(inputBlock, InitialPermutation, false, false);

        for (int i = 0; i < 16; i++)
        {
            block = _feistelNetwork.PerformEncryptConversion(block, _roundKeys[16 - i - 1]);
        }

        int halfSize = block.Length / 2;
        byte[] output = new byte[block.Length];
        Array.Copy(block, halfSize, output, 0, halfSize);
        Array.Copy(block, 0, output, halfSize, halfSize);
        return BitFunctions.Permutation(output, InverseInitialPermutation, false, false);

    }

    public void SetRoundKeys(byte[][] roundKeys)
    {
        ValidateRoundKeys(roundKeys);
        _roundKeys = roundKeys;
    }

    private static void ValidateInputBlock(byte[] block)
    {
        if (block.Length != 8)
        {
            throw new ArgumentException($"DES block must be 8 bytes, but got {block.Length} bytes", nameof(block));
        }
    }

    private static void ValidateRoundKeys(byte[][] roundKeys)
    {
        if (roundKeys.Length != 16)
        {
            throw new ArgumentException($"DES round keys must have length 16, but got {roundKeys.Length}");
        }

        for (int i = 0; i < roundKeys.Length; i++)
        {
            if (roundKeys[i].Length != 6)
            {
                throw new ArgumentException($"DES round key must has length 6 bytes, but got {roundKeys[i].Length}");
            }
        }
    }
}