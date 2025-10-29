namespace CryptoLabs.Utility.Paddings;

public enum PaddingMode
{
    Zeros,
    ANSI_X923,
    PKCS7, 
    ISO10126
}

public interface IPadding
{
    public byte[] ApplyPadding(byte[] block, int blockSize);
    public byte[] RemovePadding(byte[] block, int blockSize);
    PaddingMode Mode { get; }
}

