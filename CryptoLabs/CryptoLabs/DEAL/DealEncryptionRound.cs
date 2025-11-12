using CryptoLabs.DES;
using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.DEAL;

public class DealEncryptionRound: IEncryptionRound
{
    private readonly DESAlgorithm _des;
    private readonly DESKeyExpander _keyExpander = new();

    public DealEncryptionRound()
    {
        byte[][] initialKeys = new byte[16][];
        for (int i = 0; i < 16; i++)
        {
            initialKeys[i] = new byte[6];
        }
        _des = new DESAlgorithm(initialKeys);
    }
    
    public byte[] PerformEncryptConversion(byte[] inputBlock, byte[] roundKey)
    {
        byte[][] desRoundKeys = _keyExpander.GenerateRoundKeys(roundKey);
        _des.SetRoundKeys(desRoundKeys);
        return _des.Encrypt(inputBlock);
    }
}