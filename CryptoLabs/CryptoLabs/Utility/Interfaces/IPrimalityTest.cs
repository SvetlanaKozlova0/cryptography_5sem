namespace CryptoLabs.Utility.Interfaces;
using System.Numerics;

public interface IPrimalityTest
{
    bool Perform(BigInteger testedValue, double minProbability);
}