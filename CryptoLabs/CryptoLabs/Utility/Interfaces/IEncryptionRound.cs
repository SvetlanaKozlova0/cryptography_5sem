namespace CryptoLabs.Utility.Interfaces;

public interface IEncryptionRound
{
    byte[] PerformEncryptConversion(byte[] inputBlock, byte[] roundKey);
}