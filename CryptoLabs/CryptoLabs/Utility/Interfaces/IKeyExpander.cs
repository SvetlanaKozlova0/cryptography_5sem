namespace CryptoLabs.Utility.Interfaces;

public interface IKeyExpander
{
    public byte[][] GenerateRoundKeys(byte[] inputKey);
}