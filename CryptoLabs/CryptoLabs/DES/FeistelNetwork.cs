using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.DES;

public class FeistelNetwork: IEncryptionRound
{
        private static readonly byte[,,] SBoxes = new byte[, , ]
    {
        {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };
    
    private static readonly uint[] ExpansionTable =
    [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ];

    private static readonly uint[] PermutationTable =
    [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ];

    byte[] ExpansionFunction(byte[] input)
    {
        ValidateExpansionInput(input);
        return BitFunctions.Permutation(input, ExpansionTable, false, false);
    }

    private byte ExtractSixBits(byte[] input, int index)
    {
        if (index < 0 || index >= 8)
        {
            throw new ArgumentOutOfRangeException(nameof(index),
                $"Index for extracting 6 bits must be between 0 and 7, but got {index}");
        }
        int bitPos = index * 6;
        int byteIndex = bitPos / 8;
        int bitOffset = bitPos % 8;
        if (byteIndex >= input.Length)
        {
            return 0;
        }
        ushort bits;
        if (byteIndex == input.Length - 1)
        {
            bits = (ushort)(input[byteIndex] << 8);
        }
        else
        {
            bits = (ushort)((input[byteIndex] << 8) | input[byteIndex + 1]);
        }
        bits <<= bitOffset;
        bits >>= 10;
        return (byte)(bits & 0x3F);
    }

    byte PerformOneSBlock(byte input, int index)
    {
        if (index < 0 || index >= 8)
        {
            throw new ArgumentOutOfRangeException(nameof(index), $"S-box index must be between 0 and 7, but  got {index}");
        }
        int row = ((input & 0x20) >> 4) | (input & 0x01);
        int column = (input & 0x1E) >> 1;
        return SBoxes[index, row, column];
    }
    
    byte[] PerformSBlocks(byte[] input)
    {
        if (input.Length != 6)
        {
            throw new ArgumentOutOfRangeException(nameof(input),
                $"S-box input must be 6 bytes, but got {input.Length}");
        }
        byte[] result = new byte[4];
        for (int i = 0; i < 8; i++)
        {
            byte sixBits = ExtractSixBits(input, i);
            byte fourBits = PerformOneSBlock(sixBits, i);
            if (i % 2 == 0)
            {
                result[i / 2] = (byte)(fourBits << 4);
            }
            else
            {
                result[i / 2] |= fourBits;
            }
        }
        return result;
    }
    
    
    byte[] FeistelFunction(byte[] input, byte[] key)
    {
        if (input.Length != 4)
        {
            throw new ArgumentException($"Feistel function input must be 4 bytes, but got {input.Length}");
        }
        byte[] extended = ExpansionFunction(input);
        byte[] xored = BitXor(extended, key);
        byte[] sBoxed = PerformSBlocks(xored);
        byte[] permuted = BitFunctions.Permutation(sBoxed, PermutationTable, false, false);
        return permuted;
    }

    byte[] BitXor(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            throw new ArgumentException(
                $"Lengths of blocks for bit xor must be the same, but got {a.Length}, {b.Length}");
        }
        byte[] result = new byte[a.Length];
        for (int i = 0; i < a.Length; ++i)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }
    
    public byte[] PerformEncryptConversion(byte[] inputBlock, byte[] roundKey)
    {
        ValidateInput(inputBlock, roundKey);
        int halfSize = inputBlock.Length / 2;
        byte[] left = new byte[halfSize];
        byte[] right = new byte[halfSize];
        for (int i = 0; i < halfSize; i++)
        {
            left[i] = inputBlock[i];
            right[i] = inputBlock[i + halfSize];
        }
        byte[] feistelResult = FeistelFunction(right, roundKey);
        byte[] newRight = BitXor(left, feistelResult);
        byte[] result = new byte[inputBlock.Length];
        for (int i = 0; i < halfSize; ++i)
        {
            result[i] = right[i];
            result[i + halfSize] = newRight[i];
        }
        return result;
    }

    private static void ValidateInput(byte[] input, byte[] roundKey)
    {
        if (input.Length != 8)
        {
            throw new ArgumentException($"Input block length for Feistel Network must be 8, but got {input.Length}");
        }

        if (roundKey.Length != 6)
        {
            throw new ArgumentException($"Round key length for Feistel Network must be 6, but got {roundKey.Length}");
        }
    }

    private static void ValidateExpansionInput(byte[] input)
    {
        if (input.Length != 4)
        {
            throw new ArgumentException($"Expansion input for Feistel Network must be 4, but got {input.Length}");
        }
    }
}