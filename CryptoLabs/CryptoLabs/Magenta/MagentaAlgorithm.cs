using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.Magenta;

using BF = BitFunctions;

public class MagentaAlgorithm: ISymmetricCipher
{
    private byte[][] _roundKeys;
    private byte[] _sBox; // необходимо инициализировать
    
    
    public byte[] Encrypt(byte[] inputBlock)
    {
        throw new NotImplementedException();
    }

    
    public byte[] Decrypt(byte[] inputBlock)
    {
        throw new NotImplementedException();
    }

    
    public void SetRoundKeys(byte[][] roundKeys)
    {
        _roundKeys = roundKeys;
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
        byte[] concatenation = new byte[2];
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
}