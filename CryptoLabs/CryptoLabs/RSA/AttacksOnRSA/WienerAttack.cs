namespace CryptoLabs.RSA.AttacksOnRSA;

using System.Numerics;
using CF = Utility.MathUtils.ContinuedFraction;
using BM = Utility.MathUtils.BasicMathFunctions;


public static class WienerAttack
{
    public static (BigInteger d, BigInteger phi, List<(BigInteger k, BigInteger d)> steps)
        Attack(BigInteger e, BigInteger n)
    {
        
        if (e <= 0 || n <= 1)
        {
            throw new ArgumentException("Invalid RSA public key parameters.");
        }

        var coefficients = CF.CoefficientsByGcd(e, n);
        var steps = new List<(BigInteger k, BigInteger d)>();

        BigInteger prevPrevNum = 0, prevNum = 1;
        BigInteger prevPrevDen = 1, prevDen = 0;

        foreach (var coefficient in coefficients)
        {
            var k = coefficient * prevNum + prevPrevNum; 
            var d = coefficient * prevDen + prevPrevDen; 

            steps.Add((k, d));

            if (k == 0 || d <= 0)
            {
                (prevPrevNum, prevNum) = (prevNum, k);
                (prevPrevDen, prevDen) = (prevDen, d);
                continue;
            }

            var candidateMultiplyOfPhi = e * d - 1;
            
            if (candidateMultiplyOfPhi % k != 0)
            {
                (prevPrevNum, prevNum) = (prevNum, k);
                (prevPrevDen, prevDen) = (prevDen, d);
                continue;
            }

            var phi = candidateMultiplyOfPhi / k;
            
            var sumPq = n - phi + 1; 

            var (p, q) = BM.SolveQuadraticEquation(BigInteger.One, sumPq, n);
            
            if (p is not null && q is not null && p * q == n)
            {
                return (d, phi, steps);
            }
            
            (prevPrevNum, prevNum) = (prevNum, k);
            (prevPrevDen, prevDen) = (prevDen, d);
        }

        throw new ArgumentException("Wiener's attack cannot recover the private key.");
    }
}
