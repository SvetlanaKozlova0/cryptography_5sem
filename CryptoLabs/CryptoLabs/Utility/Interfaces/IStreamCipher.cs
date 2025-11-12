namespace CryptoLabs.Utility.Interfaces;

public interface IStreamCipher
{
    public void Initialize(byte[] key);
    
    public byte[] Encrypt(byte[] input);

    public byte[] Decrypt(byte[] input);
}