namespace CryptoLabs.RC4;

using Utility.Interfaces;

public class RC4Algorithm: IStreamCipher
{
    private static readonly int SBlockSize = 256;
    private byte[] _sBlock = new byte[SBlockSize];
    private int _i;
    private int _j;
    private bool _isInitialized = false;
    
    public void Initialize(byte[] key)
    {
        if (key.Length < 1 || key.Length > 256)
        {
            throw new ArgumentException($"Key length must be between 8 and 2048 bits, but got {key.Length * 8} bits");
        }
        _sBlock = new byte[SBlockSize];
        for (int i = 0; i < SBlockSize; i++)
        {
            _sBlock[i] = (byte)i;
        }
        int j = 0;
        for (int i = 0; i < SBlockSize; i++)
        {
            j = (j + _sBlock[i] + key[i % key.Length]) % SBlockSize;
            (_sBlock[i], _sBlock[j]) = (_sBlock[j], _sBlock[i]);
        }
        _i = _j = 0;
        _isInitialized = true;
    }

    public byte[] Encrypt(byte[] input)
    {
        if (!_isInitialized)
        {
            throw new InvalidOperationException("Need to initialize algorithm before using");
        }
        byte[] output = new byte[input.Length];
        for (int k = 0; k < input.Length; k++)
        {
            output[k] = (byte)(input[k] ^ GetKeyStream());
        }
        return output; 
    }

    public byte[] Decrypt(byte[] input)
    {
        return Encrypt(input); 
    }

    private byte GetKeyStream()
    {
        _i = (_i + 1) % SBlockSize;
        _j = (_j + _sBlock[_i]) % SBlockSize;
        (_sBlock[_i], _sBlock[_j]) = (_sBlock[_j], _sBlock[_i]);
        return _sBlock[(_sBlock[_i] + _sBlock[_j]) % SBlockSize];
    }
}