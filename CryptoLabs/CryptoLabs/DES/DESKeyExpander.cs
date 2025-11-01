using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.DES;

public class DESKeyExpander: IKeyExpander
{
    private static readonly uint[] PermutedChoice1 =
    [
        57, 49, 41, 33, 25, 17, 9,
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
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ];


    private static int GetC0(byte[] key)
    {
        int c = 0;
        for (int i = 0; i < 3; i++)
        {
            c = (c << 8) | (key[i] & 0xff);
        }
        c = (c << 4) | ((key[3] & 0xf0) >> 4);
        return c & 0x0fffffff;
    }

    private static int GetD0(byte[] key)
    {
        int d = (key[3] & 0x0f);
        for (int i = 4; i < 7; i++)
        {
            d = (d << 8) | (key[i] & 0xff);
        }
        return d &  0x0fffffff;
    }

    private static int LeftShift(int value, int shift)
    {
        return ((value << shift) | (value >> (28 - shift))) & 0x0fffffff;
    }

    private static byte[] MergeCD(int c, int d)
    {
        long cd = (((long)c) << 28) | (uint)(d & 0x0fffffff);
        byte[] merged = new byte[7];
        for (int i = 0; i < 7; i++)
        {
            merged[i] = (byte)((cd >> ((6 - i) * 8)) & 0xff);
        }
        return merged;
    }
    
    public byte[][] GenerateRoundKeys(byte[] inputKey)
    {
        byte[] permutedKey = BitFunctions.Permutation(inputKey, PermutedChoice1, false, false);
        
        int c = GetC0(permutedKey);
        int d = GetD0(permutedKey);
        byte[][] roundKeys = new byte[16][];
        for (int i = 0; i < 16; i++)
        {
            c = LeftShift(c, Shifts[i]);
            d = LeftShift(d, Shifts[i]);
            byte[] merged = MergeCD(c, d);
            byte[] roundKey = BitFunctions.Permutation(merged, PermutedChoice2, false, false);
            roundKeys[i] = roundKey;
        }
        return roundKeys;

    }
}