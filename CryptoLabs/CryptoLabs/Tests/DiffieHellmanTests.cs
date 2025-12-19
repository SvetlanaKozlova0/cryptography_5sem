using CryptoLabs.Utility.MathUtils;

namespace CryptoLabs.Tests;
using DiffieHellman;

public static class DiffieHellmanTests
{
    public static void Demonstration()
    {
        var parameters = new ClassicalDiffieHellmanParameters();
        var p = parameters.GetP();
        var g = parameters.GetG();
        
        Console.WriteLine("Diffie-Hellman parameters:");
        Console.WriteLine($"P (module): {p.ToString().Substring(0, 50)}...");
        Console.WriteLine($"G (generator): {g}");
        Console.WriteLine();

        var generator = new CustomRandomNumberGenerator();
        var dhProtocol = new DiffieHellmanProtocol(p, g, generator);
        
        Console.WriteLine("ALICE:");
        var alicePrivateKey = dhProtocol.GeneratePrivateKey();
        Console.WriteLine($"Private key: {alicePrivateKey.ToString().Substring(0, 30)}...");

        var alicePublicKey = dhProtocol.GeneratePublicKey(alicePrivateKey);
        Console.WriteLine($"Public key: {alicePublicKey.ToString().Substring(0, 30)}...");
        Console.WriteLine();
        
        Console.WriteLine("BOB:");
        var bobPrivateKey = dhProtocol.GeneratePrivateKey();
        Console.WriteLine($"Private key: {bobPrivateKey.ToString().Substring(0, 30)}...");

        var bobPublicKey = dhProtocol.GeneratePublicKey(bobPrivateKey);
        Console.WriteLine($"Public key: {bobPublicKey.ToString().Substring(0, 30)}...");
        Console.WriteLine();
        
        Console.WriteLine("Key exchange...");
        Console.WriteLine("Alice sends her public key to Bob...");
        Console.WriteLine("Bob sends his public key to Alice...");
        Console.WriteLine();
        
        var aliceSharedSecret = dhProtocol.GenerateSharedSecret(bobPublicKey, alicePrivateKey);
        Console.WriteLine($"Alice shared secret: {aliceSharedSecret.ToString().Substring(0, 30)}...");
        
        var bobSharedSecret = dhProtocol.GenerateSharedSecret(alicePublicKey, bobPrivateKey);
        Console.WriteLine($"Bob shared secret: {bobSharedSecret.ToString().Substring(0, 30)}...");
        Console.WriteLine();
        
        Console.WriteLine("Check...");
        var secretsMatch = aliceSharedSecret == bobSharedSecret;
        
        Console.WriteLine(secretsMatch ? 
            "Secrets match! The protocol works correctly." : 
            "Secrets not match! The protocol doesn't works correctly.");
    }
}