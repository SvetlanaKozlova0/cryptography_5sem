using CryptoLabs.Tests;

try
{
    //RSABasicTests.TestAsyncSecond().GetAwaiter().GetResult();
    //Console.WriteLine("everything is ok!");
    //DESTests.TestAsyncSecond().GetAwaiter().GetResult();
    //Console.WriteLine("everything is okay");
    //RSABasicTests.RunMyTests();
    //DESTests.TestAsyncSecond().GetAwaiter().GetResult();
    //DifferentTests.TestWienerAttack();
    //RijndaelBasicTests.TestJPGFile();
    RijndaelBasicTests.RunTests();
    RijndaelBasicTests.TestJPGFile();
}

catch (Exception ex)

{
    Console.WriteLine($"Test failed: {ex.Message}");
}