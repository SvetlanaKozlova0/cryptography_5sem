using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.DEAL;

public class DealAlgorithm: ISymmetricCipher
{
    private byte[][] _roundKeys;
    private readonly DealEncryptionRound _encryptionRound = new();

    public int GetBlockSize()
    {
        return 16;
    }
    
    public byte[] Encrypt(byte[] inputBlock)
    {
        if (inputBlock.Length != 16)
        {
            throw new ArgumentException(
                $"Length of input block for DEAL must be 16 bytes, but got {inputBlock.Length}");
        }
        byte[] left = new byte[8];
        byte[] right = new byte[8];
        
        Array.Copy(inputBlock, 0, left, 0, 8);
        Array.Copy(inputBlock, 8, right, 0, 8);

        int rounds = _roundKeys.Length;
        for (int i = 0; i < rounds; i++)
        {
            byte[] temp = left;
            left = right;
            byte[] fResult = _encryptionRound.PerformEncryptConversion(right, _roundKeys[i]);
            right = BitFunctions.XorBlocks(temp, fResult, 8);
        }

        byte[] output = new byte[16];
        Array.Copy(left, 0, output, 0, 8);
        Array.Copy(right, 0, output, 8, 8);
        return output;
    }

    public byte[] Decrypt(byte[] inputBlock)
    {
        if (inputBlock.Length != 16)
        {
            throw new ArgumentException(
                $"Length of input block for DEAL must be 16 bytes, but got {inputBlock.Length}");
        }
        byte[] left = new byte[8];
        byte[] right = new byte[8];
        Array.Copy(inputBlock, 0, left, 0, 8);
        Array.Copy(inputBlock, 8, right, 0, 8);
        int rounds = _roundKeys.Length;
        for (int i = rounds - 1; i >= 0; i--)
        {
            byte[] temp = right;
            right = left;
            byte[] fResult = _encryptionRound.PerformEncryptConversion(left, _roundKeys[i]);
            left = BitFunctions.XorBlocks(temp, fResult, 8);
        }
        byte[] output = new byte[16];
        Array.Copy(left, 0, output, 0, 8);
        Array.Copy(right, 0, output, 8, 8);
        return output;
    }

    public void SetRoundKeys(byte[][] roundKeys)
    {
        _roundKeys = roundKeys;
    }
}