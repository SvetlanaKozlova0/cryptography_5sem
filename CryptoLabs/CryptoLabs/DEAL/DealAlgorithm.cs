using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.DEAL;

public class DealAlgorithm: ISymmetricCipher
{
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
        throw new NotImplementedException();
    }
}