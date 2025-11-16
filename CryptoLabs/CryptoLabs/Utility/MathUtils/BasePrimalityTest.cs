using System.Numerics;
using CryptoLabs.Utility.Interfaces;

namespace CryptoLabs.Utility.MathUtils;

public abstract class BasePrimalityTest: IPrimalityTest
{
    public bool Perform(BigInteger testedValue, double minProbability)
    {
        if (testedValue < 2)
        {
            return false;
        }

        if (testedValue == 2)
        {
            return true;
        }

        if (testedValue.IsEven)
        {
            return false;
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
        throw new NotImplementedException();
    }
    
    protected abstract bool PerformIteration(BigInteger n);

    protected abstract double CalculateProbability(int n);
    
    public static BigInteger GenerateRandomNumber(BigInteger n)
    {
        Random random = new Random();
        byte[] bytes = n.ToByteArray();
        BigInteger result;
        do
        {
            random.NextBytes(bytes);
            bytes[bytes.Length - 1] &= 0x7F;
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
        BigInteger a = GenerateRandomNumber(n - 1);
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

    protected override double CalculateProbability(int n)
    {
        throw new NotImplementedException();
    }
}


public class SolovayStrassenTest : BasePrimalityTest
{
    protected override bool PerformIteration(BigInteger n)
    {
        BigInteger a = GenerateRandomNumber(n);
        if (NumberTheoryFunctions.EuclideanAlgorithm(a, n) != 1)
        {
            return false;
        }

        if (NumberTheoryFunctions.ModPow(a, (n - 1) / 2, n) !=
            NumberTheoryFunctions.JacobiSymbol(a, n))
        {
            return false;
        }
        return true;
    }

    protected override double CalculateProbability(int n)
    {
        throw new NotImplementedException();
    }
}


public class FermatTest : BasePrimalityTest
{
    protected override bool PerformIteration(BigInteger n)
    {
        BigInteger a = GenerateRandomNumber(n);
        if (NumberTheoryFunctions.EuclideanAlgorithm(a, n) != 1)
        {
            return false;
        }

        if (NumberTheoryFunctions.ModPow(a, n - 1, n) != 1)
        {
            return false;
        }
        return true;
    }

    protected override double CalculateProbability(int n)
    {
        return 1 - 1 / Math.Pow(2, n);
        throw new NotImplementedException();
    }
}