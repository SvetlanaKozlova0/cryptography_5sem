using CryptoLabs.AES.Utility;
using CryptoLabs.Utility.Interfaces;
using CryptoLabs.AES.Parameters;

using GF = CryptoLabs.Utility.MathUtils.PolynomialOverGF;

namespace CryptoLabs.AES;

public class AESAlgorithm: ISymmetricCipher
{
    private int nb = 4;
    private byte[][] _roundKeys;
    
    AESBoxGenerator _box;
    AESPoly polynomials = new();
    

    public AESAlgorithm(AESBoxGenerator aesBoxGenerator)
    {
        _box = aesBoxGenerator;
    }
    
    
    public byte[] Encrypt(byte[] inputBlock)
    {
        if (inputBlock.Length != 16)
        {
            throw new ArgumentException("Input block length must be 16 bytes.");
        }
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
        byte[] temp = new byte[block.Length];
        Array.Copy(block, temp, block.Length);
        for (var r = 1; r < 4; r++)
        {
            for (var c = 0; c < nb; c++)
            {
                var pos = (c - r + nb) % nb;
                block[r + 4 * pos] = (byte)(temp[r + 4 * c] & 0xFF);
            }
        }
    }

    
    private void InvShiftRows(byte[] block)
    {
        byte[] temp = new byte[block.Length];
        Array.Copy(block, temp, block.Length);
        for (var r = 1; r < 4; r++)
        {
            for (var c = 0; c < nb; c++)
            {
                var pos = (c + r) % nb;
                block[r + 4 * pos] = (byte)(temp[r + 4 * c] & 0xFF);
            }
        }
    }

    
    private void MixColumns(byte[] block)
    {
        for (var i = 0; i < nb; i++)
        {
            var a3 = block[4 * i + 3];
            var a2 = block[4 * i + 2];
            var a1 = block[4 * i + 1];
            var a0 = block[4 * i];
            var poly = new GF(a3, a2, a1, a0);
            poly = GF.Mult(poly, polynomials.MixColumnsPoly, _box.Polynomial);
            block[4 * i + 3] = poly.a3;
            block[4 * i + 2] = poly.a2;
            block[4 * i + 1] = poly.a1;
            block[4 * i] = poly.a0;
        }
    }
    
    
    private void InvMixColumns(byte[] block)
    {
        for (var i = 0; i < nb; i++)
        {
            var a3 = block[4 * i + 3];
            var a2 = block[4 * i + 2];
            var a1 = block[4 * i + 1];
            var a0 = block[4 * i];
            var poly = new GF(a3, a2, a1, a0);
            poly = GF.Mult(poly, polynomials.InvMixColumnsPoly, _box.Polynomial);
            block[4 * i + 3] = poly.a3;
            block[4 * i + 2] = poly.a2;
            block[4 * i + 1] = poly.a1;
            block[4 * i] = poly.a0;
        }
    }
}