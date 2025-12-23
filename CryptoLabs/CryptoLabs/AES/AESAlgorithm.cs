using CryptoLabs.AES.Utility;
using CryptoLabs.Utility.Interfaces;
using CryptoLabs.AES.Parameters;

using GF = CryptoLabs.Utility.MathUtils.PolynomialOverGF;

namespace CryptoLabs.AES;

public class RijndaelAlgorithm: ISymmetricCipher
{
    private readonly int _nb;
    private byte[][] _roundKeys;
    
    private readonly RijndaelBoxGenerator _box;
    private readonly RijndaelPoly _polynomials = new();
    

    public RijndaelAlgorithm(RijndaelBoxGenerator aesBoxGenerator, int nb = 4)
    {
        _box = aesBoxGenerator;
        if (nb != 4 && nb != 6 && nb != 8)
            throw new ArgumentException("Nb must be 4, 6 or 8.");
        _nb = nb;
    }


    public int GetBlockSize() => 4 * _nb;

    
    public byte[] Encrypt(byte[] inputBlock)
    {
        if (inputBlock.Length != GetBlockSize())
            throw new ArgumentException($"Input block length must be {GetBlockSize()} bytes.");

        byte[] state = new byte[inputBlock.Length];
        Array.Copy(inputBlock, state, state.Length);
        AddRoundKey(state, _roundKeys[0]);
        for (var i = 1; i < _roundKeys.Length - 1; i++)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, _roundKeys[i]);
        }
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, _roundKeys[^1]);
        return state;
    }

    
    public byte[] Decrypt(byte[] inputBlock)
    {
        if (inputBlock.Length != 16)
        {
            throw new ArgumentException("Input block length must be 16 bytes.");
        }
        byte[] state = new byte[inputBlock.Length];
        Array.Copy(inputBlock, state, state.Length);
        AddRoundKey(state, _roundKeys[^1]);
        InvShiftRows(state);
        InvSubBytes(state);
        for (var i = _roundKeys.Length - 2; i > 0; i--)
        {
            AddRoundKey(state, _roundKeys[i]);
            InvMixColumns(state);
            InvShiftRows(state);
            InvSubBytes(state);
        }
        AddRoundKey(state, _roundKeys[0]);
        return state;
    }
    
    
    public void SetRoundKeys(byte[][] roundKeys)
    {
        if (roundKeys.Length != 11 && roundKeys.Length != 13 && roundKeys.Length != 15)
        {
            throw new ArgumentException($"Need 11 / 13 / 15 " +
                                        $"round keys for AES, but got {roundKeys.Length}.");
        }
        _roundKeys = roundKeys;
    }
    
    
    private static void AddRoundKey(byte[] state, byte[] roundKey)
    {
        if (roundKey.Length != state.Length)
        {
            throw new ArgumentException($"Round key length and State length must be the same," +
                                        $"but got: {roundKey.Length}, {state.Length}.");
        }
        for (var i = 0; i < state.Length; i++)
        {
            state[i] = (byte)(roundKey[i] ^ state[i]);
        }
    }

    
    private void SubBytes(byte[] block)
    {
        var sBox = _box.SBox();
        for (var i = 0; i < block.Length; i++)
        {
            block[i] = (sBox[block[i]]);
        }
    }

    
    private void InvSubBytes(byte[] block)
    {
        var invBox = _box.InvSBox();
        for (var i = 0; i < block.Length; i++)
        {
            block[i] = (invBox[block[i]]);
        }
    }
    

    private void ShiftRows(byte[] block)
    {
        var temp = (byte[])block.Clone();
        var shifts = GetShiftOffsets();

        for (int r = 1; r < 4; r++)
        {
            int shift = shifts[r];
            for (int c = 0; c < _nb; c++)
            {
                int src = r + 4 * c;
                int dstCol = (c - shift + _nb) % _nb;
                int dst = r + 4 * dstCol;
                block[dst] = temp[src];
            }
        }
    }


    
    private void InvShiftRows(byte[] block)
    {
        var temp = (byte[])block.Clone();
        var shifts = GetShiftOffsets();

        for (int r = 1; r < 4; r++)
        {
            int shift = shifts[r];
            for (int c = 0; c < _nb; c++)
            {
                int src = r + 4 * c;
                int dstCol = (c + shift) % _nb;
                int dst = r + 4 * dstCol;
                block[dst] = temp[src];
            }
        }
    }

    
    private void MixColumns(byte[] block)
    {
        for (var i = 0; i < _nb; i++)
        {
            var a3 = block[4 * i + 3];
            var a2 = block[4 * i + 2];
            var a1 = block[4 * i + 1];
            var a0 = block[4 * i];
            var poly = new GF(a3, a2, a1, a0);
            poly = GF.Mult(poly, _polynomials.MixColumnsPoly, _box.Polynomial);
            block[4 * i + 3] = poly.a3;
            block[4 * i + 2] = poly.a2;
            block[4 * i + 1] = poly.a1;
            block[4 * i] = poly.a0;
        }
    }
    
    
    private void InvMixColumns(byte[] block)
    {
        for (var i = 0; i < _nb; i++)
        {
            var a3 = block[4 * i + 3];
            var a2 = block[4 * i + 2];
            var a1 = block[4 * i + 1];
            var a0 = block[4 * i];
            var poly = new GF(a3, a2, a1, a0);
            poly = GF.Mult(poly, _polynomials.InvMixColumnsPoly, _box.Polynomial);
            block[4 * i + 3] = poly.a3;
            block[4 * i + 2] = poly.a2;
            block[4 * i + 1] = poly.a1;
            block[4 * i] = poly.a0;
        }
    }
    
    private int[] GetShiftOffsets()
    {
        return _nb switch
        {
            4 => new[] { 0, 1, 2, 3 },
            6 => new[] { 0, 1, 2, 3 }, 
            8 => new[] { 0, 1, 3, 4 }, 
            _ => throw new ArgumentException("Nb must be 4, 6 or 8.")
        };
    }
}