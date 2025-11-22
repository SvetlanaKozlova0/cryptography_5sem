using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.Magenta;

public class MagentaKeyExpander: IKeyExpander
{
    public byte[][] GenerateRoundKeys(byte[] inputKey)
    {
        if (inputKey.Length % 8 != 0)
        {
            throw new ArgumentException(
                $"Incorrect input key length. Must be divisible by 8, but got {inputKey.Length}.");
        }

        var count = inputKey.Length / 8;

        var result = new byte[count][];

        for (var i = 0; i < count; i++)
        {
            result[i] = new byte[8];
            Array.Copy(inputKey, i * 8, result[i], 0, 8);
        }

        return result;
    }
}

