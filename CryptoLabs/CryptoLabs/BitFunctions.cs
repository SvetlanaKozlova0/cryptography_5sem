namespace CryptoLabs;

public class BitFunctions
{
    public static byte[] Permutation(byte[] originalBlock,
        uint[] permutationBlock, bool littleEndian, bool firstIndexIsNull)
    {
            if (permutationBlock.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(permutationBlock),
                    "length of permutation block must be positive");
            }

            byte[] result = new byte[permutationBlock.Length / 8];
            int amount = permutationBlock.Length;

            for (int index = 0; index < amount; index++)
            {

                uint shiftedIndex = firstIndexIsNull ? permutationBlock[index] : permutationBlock[index] - 1;
                int srcByteIndex = (int)(shiftedIndex / 8);
                int srcBitIndex = (int)(shiftedIndex % 8);
                int dstByteIndex = index / 8;
                int dstBitIndex = index % 8;

                if (srcByteIndex >= originalBlock.Length)
                {
                    throw new ArgumentOutOfRangeException(nameof(permutationBlock), "index out of range");
                }

                byte srcMask = littleEndian ? (byte)(0x01 << srcBitIndex) : (byte)(0x80 >> srcBitIndex);

                bool currentValue = (originalBlock[srcByteIndex] & srcMask) != 0;

                byte dstMask = littleEndian ? (byte)(0x01 << dstBitIndex) : (byte)(0x80 >> dstBitIndex);

                if (currentValue)
                {
                    result[dstByteIndex] |= dstMask;
                }
                else
                {
                    result[dstByteIndex] &= (byte)~dstMask;
                }
            }
            return result;
    }

    public static byte[] XorBlocks(byte[] firstBlock, byte[] secondBlock, int BlockSize)
    {
        byte[] result = new byte[BlockSize];
        for (int i = 0; i < BlockSize; i++)
        {
            result[i] = (byte)(firstBlock[i] ^ secondBlock[i]);
        }

        return result;
    }
    
    public static byte[] Concate(byte[] x, byte[] y)
    {
        byte[] result = new byte[x.Length + y.Length];
        Array.Copy(x, 0, result, 0, x.Length);
        Array.Copy(y, 0, result, x.Length, y.Length);
        return result;
    }

    public static byte[][] Split(byte[] block)
    {
        if (block.Length % 2 != 0)
        {
            throw new ArgumentException(
                $"Split need blocks with even length, but got block with length {block.Length}.");
        }

        byte[][] result = new byte[2][];
        int half = block.Length / 2;
        
        byte[] left = new byte[half];
        Array.Copy(block, 0, left, 0, left.Length);

        byte[] right = new byte[half];
        Array.Copy(block, left.Length, right, 0, right.Length);

        result[0] = left;
        result[1] = right;

        return result;
    }
}