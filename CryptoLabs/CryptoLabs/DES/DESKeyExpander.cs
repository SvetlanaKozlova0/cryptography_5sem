using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.DES;

public class DESKeyExpander: IKeyExpander
{
    private static readonly uint[] PermutedChoice1 =
    [
        57 ,49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ];
    
    private static readonly uint[] PermutedChoice2 =
    [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ];
    
    private static readonly int[] Shifts =
    [
        1, 1, 2, 2, 2,
        2, 2, 2, 1, 2, 
        2, 2, 2, 2, 2,
        1
    ];

    private byte[] GetC0()
    {
        throw new NotImplementedException();
    }

    private byte[] GetD0()
    {
        throw new NotImplementedException();
    }

    void LeftShift(byte[] block, int shift)
    {
        throw new NotImplementedException();
    }

    byte[] MergeCD(byte[] c, byte[] d)
    {
        throw new NotImplementedException();
    }

    public byte[][] GenerateRoundKeys(byte[] inputKey)
    {
        byte[] permutedKey = BitFunctions.Permutation(inputKey, PermutedChoice1, false, false);
        byte[] c = GetC0();
        byte[] d = GetD0();

        byte[][] resultKeys = new byte[16][];

        for (int i = 0; i < 16; i++)
        {
            LeftShift(c, Shifts[i]);
            LeftShift(d, Shifts[i]);
            byte[] temp = MergeCD(c, d);
            resultKeys[i] = BitFunctions.Permutation(temp, PermutedChoice2, false, false);
        }

        return resultKeys;
    }
}