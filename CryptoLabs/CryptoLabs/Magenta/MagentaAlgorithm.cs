using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.Magenta;

using BF = BitFunctions;

public class MagentaAlgorithm: ISymmetricCipher
{
    private byte[][] _roundKeys;
    private byte[] _sBox; // необходимо инициализировать
    
    
    public byte[] Encrypt(byte[] inputBlock)
    {
        var keys = GetKeyOrder();
        var result = new byte[inputBlock.Length];
        Array.Copy(inputBlock, result, inputBlock.Length);
        foreach (byte[] key in keys)
        {
            result = OneRound(result, key);
        }

        return result;
    }

    
    public byte[] Decrypt(byte[] inputBlock)
    {
        return SwapLeftRight(Encrypt(SwapLeftRight(inputBlock)));
    }

    
    public void SetRoundKeys(byte[][] roundKeys)
    {
        _roundKeys = roundKeys;
    }

    
    private byte[][] GetKeyOrder()
    {
        return _roundKeys.Length switch
        {
            2 =>
            [
                _roundKeys[0],
                _roundKeys[0],
                _roundKeys[1],
                _roundKeys[1],
                _roundKeys[0],
                _roundKeys[0]
            ],
            3 =>
            [
                _roundKeys[0],
                _roundKeys[1],
                _roundKeys[2],
                _roundKeys[2],
                _roundKeys[1],
                _roundKeys[0]
            ],
            4 =>
            [
                _roundKeys[0],
                _roundKeys[1],
                _roundKeys[2],
                _roundKeys[3],
                _roundKeys[3],
                _roundKeys[2],
                _roundKeys[1],
                _roundKeys[0]
            ],
            _ => throw new ArgumentException($"Incorrect round keys amount: " +
                                             $"must be 2 / 3 / 4, but got {_roundKeys.Length}.")
        };
    }

    
    // возвращает элемент с номером x в S-блоке
    private byte FuncF(byte x)
    {
        return _sBox[(uint)x];
    }

    
    // возвращает f(x XOR f(y))
    private byte FuncA(byte x, byte y)
    {
        return FuncF((byte) (x ^ FuncF(y)));
    }

    
    // возвращает конкатенацию A(x, y) и A(y, x)
    private byte[] FuncPe(byte x, byte y)
    {
        var concatenation = new byte[2];
        concatenation[0] = FuncA(x, y);
        concatenation[1] = FuncA(y, x);
        return concatenation;
    }

    
    // конкатенирует результаты PE(x_i, x_(i+8))
    private byte[] FuncPi(byte[] x)
    {
        var result = new byte [x.Length];
        for (var i = 0; i < 8; i++)
        {
            var pe = FuncPe(x[i], x[i + 8]);
            result[i] = pe[0];
            result[i + 8] = pe[1];
        }

        return result;
    }

    
    private byte[] FuncT(byte[] x)
    {
        for (var i = 0; i < 4; i++)
        {
            x = FuncPi(x);
        }

        return x;
    }

    
    private byte[] copyEven(byte[] x)
    {
        var result = new byte[8];
        for (int i = 0, index = 0; i < 16; i += 2, index++)
        {
            result[index] = x[i];
        }

        return result;
    }

    
    private byte[] copyOdd(byte[] x)
    {
        var result = new byte[8];
        for (int i = 1, index = 0; i < 16; i += 2, index++)
        {
            result[index] = x[i];
        }

        return result;
    }

    
    private byte[] FuncC(int k, byte[] x)
    {
        if (k == 1)
        {
            return FuncT(x);
        }

        var leftRight = BF.Split(x);
        var left = leftRight[0];
        var right = leftRight[1];

        var firstHalf = BF.XorBlocks(left, copyEven(FuncC(k - 1, x)), left.Length);

        var secondHalf = BF.XorBlocks(right, copyOdd(FuncC(k - 1, x)), right.Length);
        
        return FuncT(BF.Concate(firstHalf, secondHalf));
    }

    
    private byte[] Func3C(byte[] x)
    {
        return copyEven(FuncC(3, x));
    }

    
    private byte[] OneRound(byte[] x, byte[] key)
    {
        var leftRight = BF.Split(x);
        return BF.Concate(leftRight[1], BF.XorBlocks(leftRight[1],
            Func3C(BF.Concate(leftRight[1], key)), leftRight[1].Length));
    }

    
    private static byte[] SwapLeftRight(byte[] block)
    {
        var leftRight = BF.Split(block);
        return BF.Concate(leftRight[1], leftRight[0]);
    }
}