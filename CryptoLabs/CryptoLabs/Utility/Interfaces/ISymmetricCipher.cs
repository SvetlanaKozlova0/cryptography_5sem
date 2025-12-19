namespace CryptoLabs.Utility.Interfaces;

public interface ISymmetricCipher
{
    void SetRoundKeys(byte[][] roundKeys);
    byte[] Encrypt(byte[] inputBlock);
    byte[] Decrypt(byte[] inputBlock);
    int GetBlockSize();
}