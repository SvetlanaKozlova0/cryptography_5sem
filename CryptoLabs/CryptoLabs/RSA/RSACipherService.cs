using CryptoLabs.Utility.MathUtils;

namespace CryptoLabs.RSA;
using System.Numerics;
public class RSACipherService(RSACipherService.PrimalityTestType testType, double minProbability, int bitLength)
{
    public enum PrimalityTestType
    {
        MillerRabin,
        SolovayStrassen,
        Fermat
    };

    private readonly RSAKeyGenerator _keyGenerator = new RSAKeyGenerator(testType, minProbability, bitLength);
    

    byte[] Encrypt(byte[] input, RSAPublicKey key)
    {
        BigInteger exponent = key.E;
        BigInteger n = key.N;
        BigInteger message = new (input);
        BigInteger result = NumberTheoryFunctions.ModPow(message, exponent, n);
        byte[] output = result.ToByteArray();
        return output;
    }

    byte[] Decrypt(byte[] input, RSAPrivateKey key)
    {
        BigInteger exponent = key.D;
        BigInteger n = key.N;
        BigInteger message = new(input);
        BigInteger result = NumberTheoryFunctions.ModPow(message, exponent, n);
        byte[] output = result.ToByteArray();
        return output;
    }

    RSAKeyPair GenerateKeyPair()
    {
        return _keyGenerator.GenerateRSAKeyPair();
    }

    private class RSAKeyGenerator(PrimalityTestType testType, double minProbability, int bitLength)
    {
        
        internal RSAKeyPair GenerateRSAKeyPair()
        {
            BigInteger p = GenerateRandomPrimeNumber();
            BigInteger q = GenerateRandomPrimeNumber();
            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);
            BigInteger e = GeneratePublicExponent(phi, 65537);
            BigInteger d = GeneratePrivateExponent(phi, e);
            RSAPublicKey publicKey = new RSAPublicKey(e, n);
            RSAPrivateKey privateKey = new RSAPrivateKey(d, n);
            return new RSAKeyPair(publicKey, privateKey);
        }

        private BigInteger GeneratePublicExponent(BigInteger phi, BigInteger e)
        {
            while (NumberTheoryFunctions.EuclideanAlgorithm(phi, e) != 1)
            {
                e = NextPrime(e);
            }

            return e;
        }

        private BigInteger GeneratePrivateExponent(BigInteger phi, BigInteger e)
        {
            NumberTheoryFunctions.BezoutIdentity(e, phi, out BigInteger d, out _);
            d %= phi;
            if (d < 0)
            {
                d += phi;
            }
            return d;
        }

        private BigInteger NextPrime(BigInteger number)
        {
            number += 2;
            while (!IsPrime(number))
            {
                number += 2;
            }

            return number;
        }

        private bool IsPrime(BigInteger number)
        {
            BasePrimalityTest test = testType switch
            {
                PrimalityTestType.Fermat => new FermatTest(),
                PrimalityTestType.MillerRabin => new MillerRabinTest(),
                PrimalityTestType.SolovayStrassen => new SolovayStrassenTest(),
                _ => throw new InvalidOperationException("Unknown primality test type"),
            };
            return test.Perform(number, minProbability);
        }
        
        private BigInteger GenerateRandomPrimeNumber()
        {
            BasePrimalityTest test = testType switch
            {
                PrimalityTestType.Fermat => new FermatTest(),
                PrimalityTestType.MillerRabin => new MillerRabinTest(),
                PrimalityTestType.SolovayStrassen => new SolovayStrassenTest(),
                _ => throw new InvalidOperationException("Unknown primality test type"),
            };
            while (true)
            {
                BigInteger candidate = BasePrimalityTest.GenerateRandomNumber(bitLength / 2);
                if (test.Perform(candidate, minProbability))
                {
                    // добавить необходимые проверки для защиты от атак
                    return candidate;
                }

                candidate += 2;
                if (candidate.GetBitLength() > bitLength / 2 + 10)
                {
                    candidate = BasePrimalityTest.GenerateRandomNumber(bitLength / 2);
                    return candidate;
                }
            }
            
        }
    }

}

public class RSAPublicKey(BigInteger e, BigInteger n)
{
    public BigInteger E { get; } = e;
    public BigInteger N { get; } = n;
}


public class RSAPrivateKey(BigInteger d, BigInteger n)
{
    public BigInteger D { get; } = d;
    public BigInteger N { get; } = n;
}


public class RSAKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey)
{
    public RSAPublicKey PublicKey = publicKey;
    public RSAPrivateKey PrivateKey = privateKey;
}