using CryptoLabs.DES;
using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.DEAL;

public class DealKeyExpander: IKeyExpander
{
    private readonly DESAlgorithm _des = new ([[]]);
    
    private static readonly byte[] Const1 = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    private static readonly byte[] Const2 = [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    private static readonly byte[] Const4 = [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    private static readonly byte[] Const8 = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    
    public byte[][] GenerateRoundKeys(byte[] inputKey)
    {
        byte[] initialKey = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
        DESKeyExpander desKeyExpander = new DESKeyExpander();
        byte[][] desRoundKeys = desKeyExpander.GenerateRoundKeys(initialKey);
        _des.SetRoundKeys(desRoundKeys);
        
        return inputKey.Length switch
        {
            16 => GenerateRoundKeys128(inputKey),
            24 => GenerateRoundKeys192(inputKey),
            32 => GenerateRoundKeys256(inputKey),
            _ => throw new ArgumentException($"The key length {inputKey.Length} is invalid. " +
                                             $"Must be 128 or 192 or 256.")
        };
    }
    
    private byte[][] GenerateRoundKeys128(byte[] inputKey)
    {
        byte[][] roundKeys = new byte[6][];
        byte[] k1 = new byte[8];
        byte[] k2 = new byte[8];
        Array.Copy(inputKey, 0, k1, 0, 8);
        Array.Copy(inputKey, 8, k2, 0, 8);
        
        // RK1 = E(K1)
        byte[] input1 = k1;
        roundKeys[0] = _des.Encrypt(input1);
        
        // RK2 = E(K2 + RK1)
        byte[] input2 = Xor2(k2, roundKeys[0]);
        roundKeys[1] = _des.Encrypt(input2);
        
        // RK3 = E(K1 + <1> + RK2)
        byte[] input3 = Xor3(k1, Const1, roundKeys[1]);
        roundKeys[2] = _des.Encrypt(input3);
        
        // RK4 = E(K2 + <2> + RK3)
        byte[] input4 = Xor3(k2, Const2, roundKeys[2]);
        roundKeys[3] = _des.Encrypt(input4);
        
        // RK5 = E(K1 + <4> + RK4)
        byte[] input5 = Xor3(k1, Const4, roundKeys[3]);
        roundKeys[4] = _des.Encrypt(input5);
        
        // RK6 = E(K2 + <8> + RK5)
        byte[] input6 = Xor3(k2, Const8, roundKeys[4]);
        roundKeys[5] = _des.Encrypt(input6);

        return roundKeys;
    }
    
    private byte[][] GenerateRoundKeys192(byte[] inputKey)
    {
        byte[][] roundKeys = new byte[6][];
        
        byte[] k1 = new byte[8];
        byte[] k2 = new byte[8];
        byte[] k3 = new byte[8];
        
        Array.Copy(inputKey, 0, k1, 0, 8);
        Array.Copy(inputKey, 8, k2, 0, 8);
        Array.Copy(inputKey, 16, k3, 0, 8);
        
        // RK1 = E(K1)
        byte[] input1 = k1;
        roundKeys[0] = _des.Encrypt(input1);
        
        // RK2 = E(K2 + RK1)
        byte[] input2 = Xor2(k2, roundKeys[0]);
        roundKeys[1] =  _des.Encrypt(input2);
        
        // RK3 = E(K3 + RK2)
        byte[] input3 = Xor2(k3, roundKeys[1]);
        roundKeys[2] = _des.Encrypt(input3);
        
        // RK4 = E(K1 + <1> + RK3) 
        byte[] input4 = Xor3(k1, Const1, roundKeys[2]);
        roundKeys[3] = _des.Encrypt(input4);
        
        // RK5 = E(K2 + <2> + RK4)
        byte[] input5 = Xor3(k2, Const2, roundKeys[3]);
        roundKeys[4] = _des.Encrypt(input5);
        
        // RK6 = E(K3 + <4> + RK5)
        byte[] input6 = Xor3(k3, Const4, roundKeys[4]);
        roundKeys[5] = _des.Encrypt(input6);

        return roundKeys;
    }

    private byte[][] GenerateRoundKeys256(byte[] inputKey)
    {
        byte[][] roundKeys = new byte[8][];
        byte[] k1 = new byte[8];
        byte[] k2 = new byte[8];
        byte[] k3 = new byte[8];
        byte[] k4 = new byte[8];
        
        Array.Copy(inputKey, 0, k1, 0, 8);
        Array.Copy(inputKey, 8, k2, 0, 8);
        Array.Copy(inputKey, 16, k3, 0, 8);
        Array.Copy(inputKey, 24, k4, 0, 8);
        
        // RK1 = E(K1)
        byte[] input1 = k1;
        roundKeys[0] = _des.Encrypt(input1);
        
        // RK2 = E(K2 + RK1)
        byte[] input2 = Xor2(k2, roundKeys[0]);
        roundKeys[1] = _des.Encrypt(input2);
        
        // RK3 = E(K3 + RK2)
        byte[] input3 = Xor2(k3, roundKeys[1]);
        roundKeys[2] = _des.Encrypt(input3);
        
        // RK4 = E(K4 + RK3)
        byte[] input4 = Xor2(k4, roundKeys[2]);
        roundKeys[3] = _des.Encrypt(input4);
        
        // RK5 = E(K1 + <1> + RK4)
        byte[] input5 = Xor3(k1, Const1, roundKeys[3]);
        roundKeys[4] = _des.Encrypt(input5);
        
        // RK6 = E(K2 + <2> + RK5)
        byte[] input6 = Xor3(k2, Const2, roundKeys[4]);
        roundKeys[5] = _des.Encrypt(input6);
        
        // RK7 = E(K3 + <4> + RK6)
        byte[] input7 = Xor3(k3, Const4, roundKeys[5]);
        roundKeys[6] = _des.Encrypt(input7);
        
        // RK8 = E(K4 + <8> + RK7)
        byte[] input8 = Xor3(k4, Const8, roundKeys[6]);
        roundKeys[7] = _des.Encrypt(input8);

        return roundKeys;
    }
    
    private byte[] Xor2(byte[] a, byte[] b)
    {
        return BitFunctions.XorBlocks(a, b, a.Length);
    }

    private byte[] Xor3(byte[] a, byte[] b, byte[] c)
    {
        byte[] d = Xor2(a, b);
        return Xor2(d, c);
    }
}