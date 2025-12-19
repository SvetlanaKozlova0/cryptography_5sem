namespace CryptoLabs.DiffieHellman;
using System.Numerics;
using Utility.MathUtils;
using NT = Utility.MathUtils.NumberTheoryFunctions;


class ClassicalDiffieHellmanParameters
{
    public BigInteger GetP()
    {
        return BigInteger.Parse(
            "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
            System.Globalization.NumberStyles.HexNumber);
    }

    public BigInteger GetG()
    {
        return 2;
    }
}


public class DiffieHellmanProtocol(BigInteger p, BigInteger g, CustomRandomNumberGenerator generator)
{
    private BigInteger _p = p, _g = g;
    private CustomRandomNumberGenerator _generator = generator;
    
    
    public BigInteger GeneratePrivateKey()
    {
        var key = _generator.GenerateRandomBigInteger(2040);
        return (key <= 1) ? 2 : key;
    }
    
    
    public BigInteger GeneratePublicKey(BigInteger privateKey)
    {
        return NT.ModPow(_g,privateKey,_p);
    }

    
    public BigInteger GenerateSharedSecret(BigInteger otherPublicKey, BigInteger myPrivateKey)
    {
        return NT.ModPow(otherPublicKey,myPrivateKey,_p);
    }
}