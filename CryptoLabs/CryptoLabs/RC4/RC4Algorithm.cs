namespace CryptoLabs.RC4;

using Utility.Interfaces;

public class RC4Algorithm: IStreamCipher
{
    private static readonly int SBlockSize = 256;
    private byte[] _sBlock = new byte[SBlockSize];
    private int _i;
    private int _j;
    private bool _isInitialized = false;
    
    public void Initialize(byte[] key)
    {
        if (key.Length < 1 || key.Length > 256)
        {
            throw new ArgumentException($"Key length must be between 8 and 2048 bits, but got {key.Length * 8} bits");
        }
        _sBlock = new byte[SBlockSize];
        for (int i = 0; i < SBlockSize; i++)
        {
            _sBlock[i] = (byte)i;
        }
        int j = 0;
        for (int i = 0; i < SBlockSize; i++)
        {
            j = (j + _sBlock[i] + key[i % key.Length]) % SBlockSize;
            (_sBlock[i], _sBlock[j]) = (_sBlock[j], _sBlock[i]);
        }
        _i = _j = 0;
        _isInitialized = true;
    }

    public byte[] Encrypt(byte[] input)
    {
        if (!_isInitialized)
        {
            throw new InvalidOperationException("Need to initialize algorithm before using");
        }
        byte[] output = new byte[input.Length];
        for (int k = 0; k < input.Length; k++)
        {
            output[k] = (byte)(input[k] ^ GetKeyStream());
        }
        return output; 
    }

    public byte[] Decrypt(byte[] input)
    {
        return Encrypt(input); 
    }

    private byte GetKeyStream()
    {
        _i = (_i + 1) % SBlockSize;
        _j = (_j + _sBlock[_i]) % SBlockSize;
        (_sBlock[_i], _sBlock[_j]) = (_sBlock[_j], _sBlock[_i]);
        return _sBlock[(_sBlock[_i] + _sBlock[_j]) % SBlockSize];
    }

    
    private static void ProcessFile(string input, string output, byte[] key, int bufferSize = 4096)
    {
        var rc4 = new RC4Algorithm();
        rc4.Initialize(key);
        using (var inputFile = new FileStream(input, FileMode.Open, FileAccess.Read))
        using (var outputFile = new FileStream(output, FileMode.Create, FileAccess.Write))
        {
            var buffer = new byte[bufferSize];
            int bytesRead;
                
            while ((bytesRead = inputFile.Read(buffer, 0, buffer.Length)) > 0)
            {
                var bufferCopy = new byte[bytesRead];
                Array.Copy(buffer, 0, bufferCopy, 0, bytesRead);
                var processedData = rc4.Encrypt(bufferCopy);
                outputFile.Write(processedData, 0, processedData.Length);
            }
        }
    }

    
    public static void EncryptFile(string input, string output, byte[] key, int bufferSize = 4096)
    {
        ProcessFile(input, output, key, bufferSize);
    }

    
    public static void DecryptFile(string input, string output, byte[] key, int bufferSize = 4096)
    {
        ProcessFile(input, output, key, bufferSize);
    }
    
    
    private static async Task ProcessFileAsync(string input, string output, byte[] key, 
        int bufferSize = 4096, CancellationToken cancellationToken = default)
    {
        var rc4 = new RC4Algorithm();
        rc4.Initialize(key);
    
        await using var inputFile = File.OpenRead(input);
        await using var outputFile = File.Create(output);
    
        var buffer = new byte[bufferSize];
        int bytesRead;
    
        while ((bytesRead = await inputFile.ReadAsync(buffer, cancellationToken)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            for (int i = 0; i < bytesRead; i++)
            {
                buffer[i] ^= rc4.GetKeyStream();
            }
        
            await outputFile.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
        }
    }
    
    
    public static Task EncryptFileAsync(string input, string output, byte[] key, 
        int bufferSize = 4096, CancellationToken cancellationToken = default)
    {
        return ProcessFileAsync(input, output, key, bufferSize, cancellationToken);
    }
    
    
    public static Task DecryptFileAsync(string input, string output, byte[] key, 
        int bufferSize = 4096, CancellationToken cancellationToken = default)
    {
        return ProcessFileAsync(input, output, key, bufferSize, cancellationToken);
    }
}