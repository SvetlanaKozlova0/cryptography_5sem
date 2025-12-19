using CryptoLabs.Utility.Interfaces;
using CryptoLabs.Utility.CipherModes;
using CryptoLabs.Utility.Paddings;

namespace CryptoLabs.Utility.CryptoContext;

public class SymmetricCryptoContext
{
    private readonly ISymmetricCipher _symmetricCipher;
    private readonly ICipherMode _cipherMode;
    private readonly IPadding _padding;
    private readonly byte[] _iv;
    private readonly object[] _parameters;
    private readonly IFileCipherMode _fileCipherMode;

    public SymmetricCryptoContext(byte[] key,
        ISymmetricCipher cipher,
        CipherMode mode,
        PaddingMode padding,
        IKeyExpander expander,
        byte[] iv,
        params object[] args)
    {
        _symmetricCipher = cipher;
        _cipherMode = CipherModeFactory.Create(mode);
        _padding = PaddingFactory.Create(padding);
        _iv = iv;
        _parameters = args;
        byte[][] roundKeys = expander.GenerateRoundKeys(key);
        _symmetricCipher.SetRoundKeys(roundKeys);
        _fileCipherMode = FileCipherModeFactory.Create(mode);
    }

    public void EncryptSync(byte[] input, ref byte[] output)
    {
        byte[] padded = _padding.ApplyPadding(input, _cipherMode.BlockSize);
        byte[] encrypted = _cipherMode.Encrypt(_symmetricCipher, padded, _iv);
        output = encrypted;
    }
    
    public byte[] EncryptSync(byte[] input)
    {
        byte[] padded = _padding.ApplyPadding(input, _cipherMode.BlockSize);
        byte[] encrypted = _cipherMode.Encrypt(_symmetricCipher, padded, _iv);
        return encrypted;
    }

    public void DecryptSync(byte[] input, ref byte[] output)
    {
        byte[] decrypted = _cipherMode.Decrypt(_symmetricCipher, input, _iv);
        byte[] unpadded = _padding.RemovePadding(decrypted, _cipherMode.BlockSize);
        output = unpadded;
    }
    
    public byte[] DecryptSync(byte[] input)
    {
        byte[] decrypted = _cipherMode.Decrypt(_symmetricCipher, input, _iv);
        byte[] unpadded = _padding.RemovePadding(decrypted, _cipherMode.BlockSize);
        return unpadded;
    }
    
    public void EncryptFile(string input, string output)
    {
        _fileCipherMode.Encrypt(_symmetricCipher, _padding, input, output, _iv);
    }

    public void DecryptFile(string input, string output)
    {
        _fileCipherMode.Decrypt(_symmetricCipher, _padding, input, output, _iv);
    }

    public async Task EncryptFileAsync(string input, string output)
    {
        await _fileCipherMode.EncryptAsync(_symmetricCipher, _padding, input, output, _iv);
    }

    public async Task DecryptFileAsync(string input, string output)
    {
        await _fileCipherMode.DecryptAsync(_symmetricCipher, _padding, input, output, _iv);
    }
}