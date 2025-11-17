using System.Numerics;
using CryptoLabs.RSA;
using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.Utility.MathUtils;

public abstract class BasePrimalityTest: IPrimalityTest
{
    public bool Perform(BigInteger testedValue, double minProbability)
    {
        if (testedValue < 2 || testedValue.IsEven)
        {
            return false;
        }

        if (testedValue == 2)
        {
            return true;
        } 
        
        int countIterations = CalculateNumberIterations(minProbability);
        
        for (int i = 0; i < countIterations; i++)
        {
            if (!PerformIteration(testedValue))
            {
                return false;
            }
        }
        return true;
    }

    protected virtual int CalculateNumberIterations(double minProbability)
    {
        int k = 1;
        
        while (CalculateProbability(k) < minProbability)
        {
            k++;
        }

        return k;
    }
    
    protected abstract bool PerformIteration(BigInteger n);

    protected abstract double CalculateProbability(int k);
    
    public static BigInteger GenerateRandomTo(BigInteger n)
    {
        Random random = new Random();
        byte[] bytes = n.ToByteArray();
        BigInteger result;
        
        do
        {
            random.NextBytes(bytes);
            bytes[^1] &= 0x7F;
            result = new BigInteger(bytes);
            
        } while (result >= n || result < 2);

        return result;
    }
}


public class MillerRabinTest: BasePrimalityTest
{
    protected override bool PerformIteration(BigInteger n)
    {
        BigInteger s = 0;
        BigInteger t = 0;
        BigInteger m = n - 1;
        
        while (m % 2 == 0)
        {
            s += 1;
            m /= 2;
        }
        
        t = m;
        
        BigInteger a = GenerateRandomTo(n - 1);
        BigInteger x = NumberTheoryFunctions.ModPow(a, t, n);
        
        if (x == 1 || x == n - 1)
        {
            return false;
        }

        for (int j = 0; j < s - 1; j++)
        {
            x = NumberTheoryFunctions.ModPow(x, 2, n);
            
            if (x == 1)
            {
                return false;
            }

            if (x == n - 1)
            {
                break;
            }
        }
        return true;
    }

    protected override double CalculateProbability(int k)
    {
        return 1 - 1 / Math.Pow(4, k);
    }

    protected override int CalculateNumberIterations(double minProbability)
    {
        return (int)Math.Ceiling(Math.Log(1 - minProbability) / Math.Log(0.25));
    }
}


public class SolovayStrassenTest : BasePrimalityTest
{
    protected override bool PerformIteration(BigInteger n)
    {
        BigInteger a = GenerateRandomTo(n);
        if (NumberTheoryFunctions.EuclideanAlgorithm(a, n) != 1)
        {
            return false;
        }

        return NumberTheoryFunctions.ModPow(a, (n - 1) / 2, n) ==
               NumberTheoryFunctions.JacobiSymbol(a, n);
    }

    protected override double CalculateProbability(int k)
    {
        return 1 - 1 / Math.Pow(2, k);
    }

    protected override int CalculateNumberIterations(double minProbability)
    {
        return (int)Math.Ceiling(Math.Log(1 - minProbability) / Math.Log(0.5));
    }
}


public class FermatTest : BasePrimalityTest
{
    protected override bool PerformIteration(BigInteger n)
    {
        BigInteger a = GenerateRandomTo(n);
        if (NumberTheoryFunctions.EuclideanAlgorithm(a, n) != 1)
        {
            return false;
        }
        return NumberTheoryFunctions.ModPow(a, n - 1, n) == 1;
    }

    protected override double CalculateProbability(int k)
    {
        return 1 - 1 / Math.Pow(2, k);
    }

    protected override int CalculateNumberIterations(double minProbability)
    {
        return (int)Math.Ceiling(Math.Log(1 - minProbability) / Math.Log(0.5));
    }
}

public static class PrimalityTestFactory
{
    public static BasePrimalityTest Create(RSACipherService.PrimalityTestType testType)
    {
        return testType switch
        {
            RSACipherService.PrimalityTestType.Fermat => new FermatTest(),
            RSACipherService.PrimalityTestType.MillerRabin => new MillerRabinTest(),
            RSACipherService.PrimalityTestType.SolovayStrassen => new SolovayStrassenTest(),
            _ => throw new ArgumentException($"Unsupported primality test type {testType}")
        };
    }
}