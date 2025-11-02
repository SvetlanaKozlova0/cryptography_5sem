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
    }

    public void EncryptSync(byte[] input, ref byte[] output)
    {
        throw new NotImplementedException();
    }

    public void DecryptSync(byte[] input, ref byte[] output)
    {
        throw new NotImplementedException();
    }

    public void EncryptAsync(byte[] input, ref byte[] output)
    {
        throw new NotImplementedException();
    }

    public void DecryptAsync(byte[] input, ref byte[] output)
    {
        throw new NotImplementedException();
    }

    public void EncryptSync(string inputFile, string outputFile)
    {
        throw new NotImplementedException();
    }

    public void DecryptSync(string inputFile, string outputFile)
    {
        throw new NotImplementedException();
    }

    public void EncryptAsync(string inputFile, string outputFile)
    {
        throw new NotImplementedException();
    }

    public void DecryptAsync(string inputFile, string outputFile)
    {
        throw new NotImplementedException();
    }
}