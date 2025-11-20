using CryptoLabs.AES.Utility;
using CryptoLabs.Utility.Interfaces;
using CryptoLabs.AES.Parameters;

namespace CryptoLabs.AES;

public class AESKeyExpander: IKeyExpander
{
    private readonly AESBoxGenerator _box;
    private AESRconGenerator _rcon;
    private AESSpecification _spec;

    
    public AESKeyExpander(AESBoxGenerator boxGenerator)
    {
        _box = boxGenerator;
    }
    
    
    public byte[][] GenerateRoundKeys(byte[] inputKey)
    {
        if (inputKey.Length != 16 && inputKey.Length != 24 && inputKey.Length != 32)
        {
            throw new ArgumentException($"Input key for generating round keys must be 16 / 24 / 32 bytes," +
                                        $"but got {inputKey.Length}.");
        }
        
        var lengthKey = inputKey.Length / 4;
        
        _spec = new AESSpecification(lengthKey);
        _rcon = new AESRconGenerator(_spec.Nb, _spec.Nr, _box.Polynomial);
        
        var countWords = _spec.Nb * (_spec.Nr + 1);
        var keySize = countWords * 4;
        
        var key = new byte[keySize];
        Array.Copy(inputKey, 0, key, 0, _spec.Nk * 4);
        
        var temp = new byte[4];
        var w = new byte[4];

        for (var i = _spec.Nk; i < countWords; i++)
        {
            var previousIndex = (i - 1) * 4;
            Array.Copy(key, previousIndex, temp, 0, 4);
            
            if (i % _spec.Nk == 0)
            {
                RotWord(temp);
                SubWord(temp);
                
                // later remove this check
                if (i / _spec.Nk < _rcon.GenerateRCon().Length)
                {
                    BitFunctions.XorBlocks(temp, _rcon.GenerateRCon()[i / _spec.Nk], temp.Length);
                }
                else
                {
                    throw new InvalidOperationException($"Invalid index for rcon.");
                }
            }
            
            else if ( i % _spec.Nk == 4 && _spec.Nk > 6)
            {
                SubWord(temp);
            }
            
            Array.Copy(key, (i - _spec.Nk) * 4, w, 0, 4);
            BitFunctions.XorBlocks(temp, w, temp.Length);
            Array.Copy(temp, 0, key, i * 4, 4);
        }
        
        return CopyKeys(key);
    }

    
    private byte[][] CopyKeys(byte[] key)
    {
        var result = new byte[_spec.Nr + 1][];
        for (var i = 0; i <= _spec.Nr; i++)
        {
            result[i] = new byte[_spec.Nb * 4]; 
            var srcIndex = _spec.Nb * 4 * i;
            var dstLength = _spec.Nb * 4;
            Array.Copy(key, srcIndex, result[i], 0, dstLength);
        }
        
        return result;
    }
    
    
    private static void RotWord(byte[] word)
    {
        if (word.Length != 4)
        {
            throw new ArgumentException($"Input array for RotWord must has 4 bytes," +
                                        $" but got length {word.Length}.");
        }
        
        var temp = word[0];
        for (var i = 0; i < 3; i++)
        {
            word[i] = word[i + 1];
        }
        word[3] = temp;
    }

    
    private void SubWord(byte[] word)
    {
        if (word.Length != 4)
        {
            throw new ArgumentException($"Input array for SubWord must has 4 bytes," +
                                        $" but got length {word.Length}.");
        }

        var sBox = _box.SBox();
        
        for (var i = 0; i < word.Length; i++)
        {
            word[i] = sBox[word[i] & 0xff];
        }
    }
}