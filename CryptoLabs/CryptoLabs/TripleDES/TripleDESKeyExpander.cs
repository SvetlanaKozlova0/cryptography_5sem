using CryptoLabs.Utility.Interfaces;
using CryptoLabs.DES;
namespace CryptoLabs.TripleDES;

public class TripleDESKeyExpander: IKeyExpander
{
    private readonly DESKeyExpander _desKeyExpander = new();
    public byte[][] GenerateRoundKeys(byte[] inputKey) => inputKey.Length switch
    {
        16 => Generate2Keys(inputKey),
        24 => Generate3Keys(inputKey),
        _ => throw new ArgumentException(
            $"Keys for Triple DES must have length 16 or 24 bytes, but got {inputKey.Length}")
    };

    private byte[][] Generate3Keys(byte[] inputKey)
    {
        byte[] key1 = new byte[8];
        byte[] key2 = new byte[8];
        byte[] key3 = new byte[8];
        
        Array.Copy(inputKey, 0, key1, 0, 8);
        Array.Copy(inputKey, 8, key2, 0, 8);
        Array.Copy(inputKey, 16, key3, 0, 8);
        
        byte[][] keys1 = _desKeyExpander.GenerateRoundKeys(key1);
        byte[][] keys2 = _desKeyExpander.GenerateRoundKeys(key2);
        byte[][] keys3 = _desKeyExpander.GenerateRoundKeys(key3);
        byte[][] allKeys = new byte[48][];
        Array.Copy(keys1, 0, allKeys, 0, 16);
        Array.Copy(keys2, 0, allKeys, 16, 16);
        Array.Copy(keys3, 0, allKeys, 32, 16);
        return allKeys;
    }

    private byte[][] Generate2Keys(byte[] inputKey)
    {
        byte[] key1 = new byte[8];
        byte[] key2 = new byte[8];
        
        Array.Copy(inputKey, 0, key1, 0, 8);
        Array.Copy(inputKey, 8, key2, 0, 8);
        
        byte[][] keys1 = _desKeyExpander.GenerateRoundKeys(key1);
        byte[][] keys2 = _desKeyExpander.GenerateRoundKeys(key2);
        
        byte[][] allKeys = new byte[48][]; 
        Array.Copy(keys1, 0, allKeys, 0, 16);
        Array.Copy(keys2, 0, allKeys, 16, 16);
        Array.Copy(keys1, 0, allKeys, 32, 16); 
    
        return allKeys;
    }
}