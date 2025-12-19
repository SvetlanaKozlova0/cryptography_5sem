using CryptoLabs.DES;

namespace CryptoLabs.TripleDES;
using CryptoLabs.Utility.Interfaces;

public class TripleDESAlgorithm: ISymmetricCipher 
{ 
        private readonly DESAlgorithm _des1;
        private readonly DESAlgorithm _des2;
        private readonly DESAlgorithm _des3;
        private readonly DESKeyExpander _keyExpander = new();

        public TripleDESAlgorithm()
        {
                byte[][] dummy = new byte[16][];
                for (int i = 0; i < 16; i++)
                {
                        dummy[i] = new byte[6];
                }

                _des1 = new DESAlgorithm(dummy);
                _des2 = new DESAlgorithm(dummy);
                _des3 = new DESAlgorithm(dummy);
        }

        public int GetBlockSize()
        {
                return 8;
        }
        
        public byte[] Encrypt(byte[] inputBlock)
        {
                if (inputBlock.Length != 8)
                {
                        throw new ArgumentException($"Triple DES block need 8 bytes, but got {inputBlock.Length}");
                }
                byte[] firstStep = _des1.Encrypt(inputBlock);
                byte[] secondStep = _des2.Decrypt(firstStep);
                return _des3.Encrypt(secondStep);
        }

        public byte[] Decrypt(byte[] inputBlock)
        {
                if (inputBlock.Length != 8)
                {
                        throw new ArgumentException($"Triple DES block need 8 bytes, but got {inputBlock.Length}");
                }
                byte[] firstStep = _des3.Decrypt(inputBlock);
                byte[] secondStep = _des2.Encrypt(firstStep);
                return _des1.Decrypt(secondStep);
        }

        public void SetRoundKeys(byte[][] roundKeys)
        {
                if (roundKeys.Length != 48)
                {
                        throw new ArgumentException($"Triple DES need 48 round keys, but got {roundKeys.Length}");
                }

                byte[][] keys1 = new byte[16][];
                byte[][] keys2 = new byte[16][];
                byte[][] keys3 = new byte[16][];
                
                Array.Copy(roundKeys, 0, keys1, 0, 16);
                Array.Copy(roundKeys, 16, keys2, 0, 16);
                Array.Copy(roundKeys, 32, keys3, 0, 16);
                
                _des1.SetRoundKeys(keys1);
                _des2.SetRoundKeys(keys2);
                _des3.SetRoundKeys(keys3);
        }
}
