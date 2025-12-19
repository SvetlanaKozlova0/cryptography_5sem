using CryptoLabs.Utility.MathUtils;
using System.Numerics;

namespace CryptoLabs.RSA;


public class RSACipherService(
    RSACipherService.PrimalityTestType testType,
    double minProbability,
    int bitLength)
{
    
    public enum PrimalityTestType
    {
        MillerRabin,
        SolovayStrassen,
        Fermat
    };
    
    private static readonly BigInteger[] CommonExponents = [65537, 17, 3, 257];
    
    private readonly RSAKeyGenerator _keyGenerator = new RSAKeyGenerator(testType, minProbability, bitLength);


    public byte[] Encrypt(byte[] input, RSAPublicKey key)
    {
        BigInteger message = new (input, isUnsigned: true);
        
        if (message >= key.N)
        {
            throw new ArgumentException("Message is too big for this generated modulus.");
        }
        
        var result = NumberTheoryFunctions.ModPow(message, key.E, key.N);
        var output = result.ToByteArray(isUnsigned: true);
        return output;
    }

    public byte[] Decrypt(byte[] input, RSAPrivateKey key)
    {
        BigInteger message = new(input, isUnsigned: true);
        
        if (message >= key.N)
        {
            throw new ArgumentException("Message is too big for this generated modulus. You can try to increase bit length.");
        }
        
        var result = NumberTheoryFunctions.ModPow(message, key.D, key.N);
        var output = result.ToByteArray(isUnsigned: true);
        return output;
    }
    
    public async Task EncryptFileAsync(
        string inputPath,
        string outputPath,
        RSAPublicKey publicKey,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(inputPath))
        {
            throw new FileNotFoundException(inputPath);
        }

        var keySizeBytes = publicKey.N.GetByteCount();
        var plainBlockSize = keySizeBytes - 1;

        var buffer = new byte[plainBlockSize];

        await using var input = new FileStream(
            inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);

        await using var output = new FileStream(
            outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);

        var originalLength = input.Length;
        await output.WriteAsync(BitConverter.GetBytes(originalLength), cancellationToken);

        int read;
        while ((read = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
        {
            
            var current = new byte[plainBlockSize];
            Array.Copy(buffer, current, read);

            var encrypted = Encrypt(current, publicKey);

            var correctCipher = new byte[keySizeBytes];
            
            Array.Copy(encrypted, correctCipher, Math.Min(encrypted.Length, keySizeBytes));

            await output.WriteAsync(correctCipher, cancellationToken);
        }
    }
    
    
    public async Task DecryptFileAsync(
        string inputPath,
        string outputPath,
        RSAPrivateKey privateKey,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(inputPath))
        {
            throw new FileNotFoundException(inputPath);
        }

        var keySizeBytes = privateKey.N.GetByteCount();
        var plainBlockSize = keySizeBytes - 1;

        var buffer = new byte[keySizeBytes];

        await using var input = new FileStream(
            inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);

        await using var output = new FileStream(
            outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);

        var bufferSize = new byte[8];
        await input.ReadAsync(bufferSize, cancellationToken);
        var remaining = BitConverter.ToInt64(bufferSize);

        while (remaining > 0)
        {
            var read = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
            
            if (read != buffer.Length)
            {
                throw new InvalidDataException("Corrupted encrypted file");
            }

            var decrypted = Decrypt(buffer, privateKey);

            var correctPlain = new byte[plainBlockSize];
            Array.Copy(decrypted, correctPlain, Math.Min(decrypted.Length, plainBlockSize));

            var toWrite = (int)Math.Min(remaining, plainBlockSize);
            await output.WriteAsync(correctPlain, 0, toWrite, cancellationToken);

            remaining -= toWrite;
        }
    }
    
    
    public RSAKeyPair GenerateKeyPair()
    {
        return _keyGenerator.GenerateRSAKeyPair();
    }
    

    private class RSAKeyGenerator(PrimalityTestType testType, double minProbability, int bitLength)
    {
        
        internal RSAKeyPair GenerateRSAKeyPair()
        {
            BigInteger p, q;
            do
            {
                p = GenerateRandomPrimeNumber();
                q = GenerateRandomPrimeNumber();
                
                
            } while (p == q || BigInteger.Abs(p - q) < (BigInteger.One << (bitLength / 2 - 100)));

            var n = p * q;
            var phi = (p - 1) * (q - 1);
                
            var e = GeneratePublicExponent(phi, 65537);
            var d = GeneratePrivateExponent(phi, e);
            
            return new RSAKeyPair(new RSAPublicKey(e, n), new RSAPrivateKey(d, n));
        }


        private static BigInteger GeneratePublicExponent(BigInteger phi, BigInteger defaultExponent)
        {
            
            foreach (var e in CommonExponents)
            {
                if (e < phi && NumberTheoryFunctions.EuclideanAlgorithm(phi, e) == 1)
                {
                    return e;
                }
            }
        
            var candidate = defaultExponent;
            for (var i = 0; i < 100 && candidate < phi; i++)
            {
                if (candidate > 1 && NumberTheoryFunctions.EuclideanAlgorithm(phi, candidate) == 1)
                {
                    return candidate;
                }
                
                candidate += 2;
                
                if (candidate > phi / 2) 
                    break;
            }
        
            throw new InvalidOperationException("Can't generate a public exponent (too many iterations).");
        }

        
        private static BigInteger GeneratePrivateExponent(BigInteger phi, BigInteger e)
        {
            NumberTheoryFunctions.BezoutIdentity(e, phi, out var d, out _);
            d %= phi;
            while (d < 0)
            {
                d += phi;
            }
            return d;
        }

        
        private BigInteger GenerateRandomPrimeNumber()
        {
            var test = PrimalityTestFactory.Create(testType);
            var number = 0;
            var maxNumber = GetMaxIterations();
            while (true)
            {
                var candidate = GenerateRandomByLen(bitLength / 2 - 1);
                if (test.Perform(candidate, minProbability))
                {
                    return candidate;
                }

                number++;
                if (number > maxNumber)
                {
                    throw new InvalidOperationException($"Can't generate a random number (too many iterations).");
                }
            }
        }

        
        private static BigInteger GenerateRandomByLen(int bitLength)
        {
            if (bitLength <= 0)
            {
                throw new ArgumentException($"Bit length must be positive, but got {bitLength}.", nameof(bitLength));
            }

            var random = new Random();
            var data = new byte[(bitLength + 7) / 8];
            
            random.NextBytes(data);
    
            if (bitLength % 8 == 0)
            {
                data[0] |= 0x80;
            }
    
            var result = new BigInteger(data);
    
            result = BigInteger.Abs(result);
    
            var mask = (BigInteger.One << bitLength) - 1;
            return result & mask;
        }
        
        
        private int GetMaxIterations()
        {
            return bitLength switch
            {
                <= 256 => 300,
                <= 384 => 500,
                <= 512 => 800,
                <= 1024 => 2000,
                _ => 5000
            };
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
    public readonly RSAPublicKey PublicKey = publicKey;
    public readonly RSAPrivateKey PrivateKey = privateKey;
}