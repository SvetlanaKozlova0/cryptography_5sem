using CryptoLabs.Utility.Interfaces;
using CryptoLabs.Utility.Paddings;
namespace CryptoLabs.Utility.CipherModes;

public interface IFileCipherMode
{
    void Encrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv);
    
    void Decrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv);
    
    Task EncryptAsync(ISymmetricCipher cipher, IPadding padding, string input, 
        string output, byte[] _iv, CancellationToken cancellationToken = default);
    
    Task DecryptAsync(ISymmetricCipher cipher, IPadding padding, string input, 
        string output, byte[] _iv, CancellationToken cancellationToken = default);
    
    CipherMode Mode { get; }
}

public class ECBFileCipherMode : IFileCipherMode
{
    public async Task EncryptAsync(
    ISymmetricCipher cipher,
    IPadding padding,
    string input,
    string output,
    byte[] _iv,
    CancellationToken cancellationToken = default) 
    {
        var blockSize = cipher.GetBlockSize();

        const int batchBlocks = 512;
        var batchBytes = batchBlocks * blockSize;

        await using var inputStream = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);
        await using var outputStream = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);

        var totalBytes = inputStream.Length;
        long processed = 0;
        var buffer = new byte[batchBytes];
    
        if (totalBytes == 0)
        {
            var padded = padding.ApplyPadding(Array.Empty<byte>(), blockSize);
            var encrypted = cipher.Encrypt(padded);
        
            await outputStream.WriteAsync(encrypted, 0, encrypted.Length, cancellationToken);
            return;
        }

        while (processed < totalBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
            if (bytesRead == 0)
            {
                break;
            }

            processed += bytesRead;
        
            var lastBatch = (processed == totalBytes);
        
            if (!lastBatch && (bytesRead % blockSize != 0))
            {
                throw new InvalidOperationException("Incorrect file reading (incomplete block before eof).");
            }


            var fullBlocks = bytesRead / blockSize;
            var tail = bytesRead % blockSize;

            var blocksCount = fullBlocks + (tail > 0 ? 1 : 0) + (lastBatch && tail == 0 ? 1 : 0);

            var plainBlocks = new byte[blocksCount][];
            var encryptedBlocks = new byte[blocksCount][];

            for (var i = 0; i < fullBlocks; i++)
            {
                plainBlocks[i] = new byte[blockSize];
            
                Buffer.BlockCopy(buffer, i * blockSize, plainBlocks[i], 0, blockSize);
            }

            var idx = fullBlocks;
            if (tail > 0)
            {
                var last = new byte[tail];
                Buffer.BlockCopy(buffer, fullBlocks * blockSize, last, 0, tail);
            
                plainBlocks[idx++] = padding.ApplyPadding(last, blockSize);
            }

            if (lastBatch && tail == 0)
            {
                plainBlocks[idx] = padding.ApplyPadding(Array.Empty<byte>(), blockSize);
            }

            Parallel.For(0, blocksCount, i =>
            {
                encryptedBlocks[i] = cipher.Encrypt(plainBlocks[i]);
            });

            for (var i = 0; i < blocksCount; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await outputStream.WriteAsync(encryptedBlocks[i], 0, encryptedBlocks[i].Length, cancellationToken);
            }
        }
    }


    public async Task DecryptAsync(
    ISymmetricCipher cipher,
    IPadding padding,
    string input,
    string output,
    byte[] _iv,
    CancellationToken cancellationToken = default)
    {
        var blockSize = cipher.GetBlockSize();

        await using var inputStream = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);
        await using var outputStream = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);
        
        var totalBytes = inputStream.Length;

        if (totalBytes == 0)
        {
            throw new ArgumentException("File to encrypt can't be empty.");
        }

        if (totalBytes % blockSize != 0)
        {
            throw new ArgumentException("The file size must be a multiple of the block size.");
        }

        const int batchBlocks = 512;             
        var batchBytes = batchBlocks * blockSize;

        var buffer = new byte[batchBytes];

        long processed = 0;

        byte[] lastDecryptedBlock = null;

        while (processed < totalBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
            
            if (bytesRead == 0)
            {
                break;
            }

            processed += bytesRead;

            if (bytesRead % blockSize != 0)
            {
                throw new InvalidOperationException("Error while file reading (invalid number of bytes read).");
            }

            var blocksCount = bytesRead / blockSize;
            var lastBatch = (processed == totalBytes);

            var decryptedBlocks = new byte[blocksCount][];

            Parallel.For(0, blocksCount, i =>
            {
                var block = new byte[blockSize];
                Buffer.BlockCopy(buffer, i * blockSize, block, 0, blockSize);

                decryptedBlocks[i] = cipher.Decrypt(block);
            });

            for (var i = 0; i < blocksCount; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var isVeryLastBlock = lastBatch && (i == blocksCount - 1);

                if (isVeryLastBlock)
                {
                    lastDecryptedBlock = decryptedBlocks[i];
                }
                else
                {
                    if (lastDecryptedBlock != null)
                    {
                        await outputStream.WriteAsync(lastDecryptedBlock, 0, lastDecryptedBlock.Length, cancellationToken);
                        lastDecryptedBlock = null;
                    }

                    await outputStream.WriteAsync(decryptedBlocks[i], 0, decryptedBlocks[i].Length, cancellationToken);
                }
            }
        }

        if (lastDecryptedBlock == null)
        {
            throw new InvalidOperationException("Invalid encrypted file (no last block).");
        }

        var unpadded = padding.RemovePadding(lastDecryptedBlock, blockSize);
        if (unpadded.Length > 0)
        {
            await outputStream.WriteAsync(unpadded, 0, unpadded.Length, cancellationToken);
        }
    }

    
    public void Encrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        var blockSize = cipher.GetBlockSize();
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            var buffer = new byte[blockSize];
            var totalBytes = inputStream.Length;
            long bytesProcessed = 0;
        
            while (bytesProcessed < totalBytes)
            {
                var bytesRead = inputStream.Read(buffer, 0, blockSize);
                bytesProcessed += bytesRead;
            
                byte[] block;
                if (bytesRead < blockSize)
                {
                    var lastBlock = new byte[bytesRead];
                    Array.Copy(buffer, lastBlock, bytesRead);
                    block = padding.ApplyPadding(lastBlock, blockSize);
                }
                else
                {
                    block = (byte[])buffer.Clone();
                }

                var encryptedBlock = cipher.Encrypt(block);
                outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
            }

            if (bytesProcessed == 0 || bytesProcessed % blockSize == 0)
            {
                var emptyBlock = new byte[0];
                var paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
                var encryptedBlock = cipher.Encrypt(paddedBlock);
                outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
            }
        }
    }

    public void Decrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        var blockSize = cipher.GetBlockSize();
    
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            var buffer = new byte[blockSize];
            var totalBytes = inputStream.Length;
            long bytesProcessed = 0;
        
            if (totalBytes == 0)
            {
                throw new ArgumentException("File to encrypt can't be empty.");
            }
        
            if (totalBytes % blockSize != 0)
            {
                throw new ArgumentException("Error while file reading (invalid file length).");
            }

            var totalBlocks = totalBytes / blockSize;
            long currentBlock = 0;

            while (bytesProcessed < totalBytes)
            {
                currentBlock++;
                var bytesRead = inputStream.Read(buffer, 0, blockSize);
                bytesProcessed += bytesRead;
            
                if (bytesRead != blockSize)
                {
                    throw new InvalidOperationException("Error while file reading (invalid number of bytes read).");
                }

                var decryptedBlock = cipher.Decrypt(buffer);
            
                if (currentBlock == totalBlocks)
                {
                    var unpadded = padding.RemovePadding(decryptedBlock, blockSize);
                
                    if (unpadded.Length > 0)
                    {
                        outputStream.Write(unpadded, 0, unpadded.Length);
                    }
                }
                else
                {
                    outputStream.Write(decryptedBlock, 0, decryptedBlock.Length);
                }
            }
        }
    }
    
    public CipherMode Mode => CipherMode.ECB;
}


public class CBCFileCipherMode : IFileCipherMode
{
    public async Task EncryptAsync(ISymmetricCipher cipher, IPadding padding, string input,
        string output, byte[] _iv, CancellationToken cancellationToken = default)
    {
        var blockSize = cipher.GetBlockSize();
        
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            var buffer = new byte[blockSize];
            var previousBlock = _iv;
            var totalBytes = inputStream.Length;
            
            await outputStream.WriteAsync(_iv, 0, _iv.Length, cancellationToken);

            var isLastBlock = false;
            
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var bytesRead = await inputStream.ReadAsync(buffer, 0, blockSize, cancellationToken);
                if (bytesRead == 0)
                {
                    break;
                } 
                
                byte[] blockToEncrypt;
                
                if (bytesRead < blockSize)
                {
                    var lastBlock = new byte[bytesRead];
                    Array.Copy(buffer, lastBlock, bytesRead);
                    blockToEncrypt = padding.ApplyPadding(lastBlock, blockSize);
                    isLastBlock = true;
                }
                else
                {
                    blockToEncrypt = (byte[])buffer.Clone();
                }

                var xoredBlock = BitFunctions.XorBlocks(blockToEncrypt, previousBlock, blockSize);
                var encryptedBlock = cipher.Encrypt(xoredBlock);
                await outputStream.WriteAsync(encryptedBlock, 0, encryptedBlock.Length, cancellationToken);
                previousBlock = encryptedBlock;

                if (isLastBlock)
                {
                    break;
                }
            }

            if (totalBytes == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var emptyBlock = new byte[0];
                var paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
                var xoredBlock = BitFunctions.XorBlocks(paddedBlock, previousBlock, blockSize);
                var encryptedBlock = cipher.Encrypt(xoredBlock);
                await outputStream.WriteAsync(encryptedBlock, 0, encryptedBlock.Length, cancellationToken);
            }
            else if (totalBytes > 0 && totalBytes % blockSize == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var emptyBlock = new byte[0];
                var paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
                var xoredBlock = BitFunctions.XorBlocks(paddedBlock, previousBlock, blockSize);
                var encryptedBlock = cipher.Encrypt(xoredBlock);
                await outputStream.WriteAsync(encryptedBlock, 0, encryptedBlock.Length, cancellationToken);
            }
        }
    }

    public async Task DecryptAsync(ISymmetricCipher cipher, IPadding padding, string input,
        string output, byte[] _iv, CancellationToken cancellationToken = default)
    {
        var blockSize = cipher.GetBlockSize();

        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            if (inputStream.Length < blockSize)
            {
                throw new InvalidOperationException("File is too small to contain valid encrypted data.");
            }

            var storedIv = new byte[blockSize];
            var ivBytesRead = await inputStream.ReadAsync(storedIv, 0, blockSize, cancellationToken);
            
            if (ivBytesRead != blockSize)
            {
                throw new InvalidOperationException("Failed to read IV from file.");
            }

            var encryptedDataSize = inputStream.Length - blockSize;

            if (encryptedDataSize == 0)
            {
                return;
            }

            if (encryptedDataSize % blockSize != 0) {
                throw new InvalidOperationException("The encrypted data size must be a multiple of the block size.");
                
            }

            var totalBlocks = encryptedDataSize / blockSize;

            var previousCiphertext = storedIv;
            var buffer = new byte[blockSize];

            for (long blockIndex = 1; blockIndex <= totalBlocks; blockIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var bytesRead = await inputStream.ReadAsync(buffer, 0, blockSize, cancellationToken);
                if (bytesRead != blockSize)
                {
                    throw new InvalidOperationException("Error while reading file: incomplete block.");
                }

                var currentCiphertext = (byte[])buffer.Clone();
                var decrypted = cipher.Decrypt(currentCiphertext);
                var plaintextBlock = BitFunctions.XorBlocks(decrypted, previousCiphertext, blockSize);

                if (blockIndex == totalBlocks)
                {
                    byte[] unpadded;
                    try
                    {
                        unpadded = padding.RemovePadding(plaintextBlock, blockSize);
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidOperationException("Failed to remove padding from the encrypted data.", ex);
                    }

                    if (unpadded.Length > 0)
                    {
                        await outputStream.WriteAsync(unpadded, 0, unpadded.Length, cancellationToken);
                    }
                }
                else
                {
                    await outputStream.WriteAsync(plaintextBlock, 0, plaintextBlock.Length, cancellationToken);
                }
                previousCiphertext = currentCiphertext;
            }
        }
    }
    
    public void Encrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        var blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            var buffer = new byte[blockSize];
            var previousBlock = _iv;
            var totalBytes = inputStream.Length;
            
            outputStream.Write(_iv, 0, _iv.Length);

            var isLastBlock = false;
            
            while (true)
            {
                var bytesRead = inputStream.Read(buffer, 0, blockSize);
                if (bytesRead == 0)
                {
                    break;
                } 
                
                byte[] blockToEncrypt;
                
                if (bytesRead < blockSize)
                {
                    var lastBlock = new byte[bytesRead];
                    Array.Copy(buffer, lastBlock, bytesRead);
                    blockToEncrypt = padding.ApplyPadding(lastBlock, blockSize);
                    isLastBlock = true;
                }
                else
                {
                    blockToEncrypt = (byte[])buffer.Clone();
                }

                var xoredBlock = BitFunctions.XorBlocks(blockToEncrypt, previousBlock, blockSize);
                var encryptedBlock = cipher.Encrypt(xoredBlock);
                outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
                previousBlock = encryptedBlock;

                if (isLastBlock)
                {
                    break;
                }
            }

            if (totalBytes == 0)
            {
                var emptyBlock = new byte[0];
                var paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
                var xoredBlock = BitFunctions.XorBlocks(paddedBlock, previousBlock, blockSize);
                var encryptedBlock = cipher.Encrypt(xoredBlock);
                outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
            }
            else if (totalBytes > 0 && totalBytes % blockSize == 0)
            {
                var emptyBlock = new byte[0];
                var paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
                var xoredBlock = BitFunctions.XorBlocks(paddedBlock, previousBlock, blockSize);
                var encryptedBlock = cipher.Encrypt(xoredBlock);
                outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
            }
        }
    }

    public void Decrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        int blockSize = cipher.GetBlockSize();

        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            if (inputStream.Length < blockSize)
            {
                throw new InvalidOperationException("File is too small to contain valid encrypted data.");
            }

            byte[] storedIv = new byte[blockSize];
            int ivBytesRead = inputStream.Read(storedIv, 0, blockSize);
            if (ivBytesRead != blockSize)
            {
                throw new InvalidOperationException("Failed to read IV from file.");
            }

            long encryptedDataSize = inputStream.Length - blockSize;

            if (encryptedDataSize == 0)
            {
                return;
            }

            if (encryptedDataSize % blockSize != 0) {
                throw new InvalidOperationException(
                "The encrypted data size must be a multiple of the block size. The file may be corrupted");}

            long totalBlocks = encryptedDataSize / blockSize;

            byte[] previousCiphertext = storedIv;
            byte[] buffer = new byte[blockSize];

            for (long blockIndex = 1; blockIndex <= totalBlocks; blockIndex++)
            {
                int bytesRead = inputStream.Read(buffer, 0, blockSize);
                if (bytesRead != blockSize)
                {
                    throw new InvalidOperationException("Error while reading file: incomplete block");
                }

                byte[] currentCiphertext = (byte[])buffer.Clone();

                byte[] decrypted = cipher.Decrypt(currentCiphertext);

                byte[] plaintextBlock = BitFunctions.XorBlocks(decrypted, previousCiphertext, blockSize);

            if (blockIndex == totalBlocks)
            {
                byte[] unpadded;
                try
                {
                    unpadded = padding.RemovePadding(plaintextBlock, blockSize);
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException(
                        "Failed to remove padding from the encrypted data. The data may be corrupted or the wrong padding scheme is used.",
                        ex);
                }

                if (unpadded.Length > 0)
                    outputStream.Write(unpadded, 0, unpadded.Length);
            }
            else
            {
                outputStream.Write(plaintextBlock, 0, plaintextBlock.Length);
            }

            previousCiphertext = currentCiphertext; 
            } 
        }
    }

    
    public CipherMode Mode => CipherMode.CBC;
}

public class PCBCFileCipherMode : IFileCipherMode
{
    
    public async Task EncryptAsync(ISymmetricCipher cipher, IPadding padding, string input,
    string output, byte[] _iv, CancellationToken cancellationToken = default)
{
    int blockSize = cipher.GetBlockSize();
    if (_iv.Length != blockSize)
    {
        throw new ArgumentException("IV size must be the same as block size.");
    }
    
    using (FileStream inputStream = File.OpenRead(input))
    using (FileStream outputStream = File.Create(output))
    {
        byte[] previousPlainText = new byte[blockSize];
        byte[] previousCiphertext = new byte[blockSize];
        
        Array.Copy(_iv, previousCiphertext, blockSize);
        Array.Clear(previousPlainText, 0, blockSize);
        
        byte[] buffer = new byte[blockSize];
        long totalBytes = inputStream.Length;
        long bytesRead = 0;
        
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            int read = await inputStream.ReadAsync(buffer, 0, blockSize, cancellationToken);
            if (read == 0) break; 
            
            bytesRead += read;
            
            byte[] currentPlaintext;
            bool isLastBlock = false;
            
            if (read < blockSize)
            {
                byte[] lastBlock = new byte[read];
                Array.Copy(buffer, lastBlock, read);
                currentPlaintext = padding.ApplyPadding(lastBlock, blockSize);
                isLastBlock = true;
            }
            else
            {
                currentPlaintext = (byte[])buffer.Clone();
                
                if (bytesRead == totalBytes)
                {
                    currentPlaintext = (byte[])buffer.Clone();
                }
            }
            
            byte[] xoredResult = BitFunctions.XorBlocks(previousPlainText, previousCiphertext, blockSize);
            byte[] xoredBlock = BitFunctions.XorBlocks(currentPlaintext, xoredResult, blockSize);
            byte[] encryptedBlock = cipher.Encrypt(xoredBlock);
            
            await outputStream.WriteAsync(encryptedBlock, 0, encryptedBlock.Length, cancellationToken);
            
            currentPlaintext.CopyTo(previousPlainText, 0);
            encryptedBlock.CopyTo(previousCiphertext, 0);
            
            if (isLastBlock) break;
        }
        
        
        if (bytesRead == 0 || bytesRead % blockSize == 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            byte[] emptyBlock = new byte[0];
            byte[] paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
            byte[] xorResult = BitFunctions.XorBlocks(previousPlainText, previousCiphertext, blockSize);
            byte[] xoredBlock = BitFunctions.XorBlocks(paddedBlock, xorResult, blockSize);
            byte[] encryptedBlock = cipher.Encrypt(xoredBlock);
            
            await outputStream.WriteAsync(encryptedBlock, 0, encryptedBlock.Length, cancellationToken);
        }
    }
}

    public async Task DecryptAsync(ISymmetricCipher cipher, IPadding padding, string input,
        string output, byte[] _iv, CancellationToken cancellationToken = default)
    {
        int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            byte[] buffer = new byte[blockSize];
            byte[] previousPlainText = new byte[blockSize];
            byte[] previousCiphertext = _iv;
            long totalBytes = inputStream.Length;
            long bytesProcessed = 0;
            Array.Clear(previousPlainText, 0, blockSize);
            
            if (totalBytes % blockSize != 0)
            {
                throw new InvalidOperationException("The file size must be a multiple of the block size.");
            }
            
            long totalBlocks = totalBytes / blockSize;
            long currentBlock = 0;

            while (bytesProcessed < totalBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                currentBlock++;
                int bytesRead = await inputStream.ReadAsync(buffer, 0, blockSize, cancellationToken);
                bytesProcessed += bytesRead;
                
                if (bytesRead != blockSize)
                {
                    throw new InvalidOperationException("error while reading file");
                }

                byte[] decryptedBlock = cipher.Decrypt(buffer);
                byte[] xorResult = BitFunctions.XorBlocks(previousPlainText, previousCiphertext, blockSize);
                byte[] xoredBlock = BitFunctions.XorBlocks(decryptedBlock, xorResult, blockSize);
                
                if (currentBlock == totalBlocks)
                {
                    byte[] unpadded = padding.RemovePadding(xoredBlock, blockSize);
                    
                    if (unpadded.Length > 0)
                    {
                        await outputStream.WriteAsync(unpadded, 0, unpadded.Length, cancellationToken);
                    }

                    xoredBlock.CopyTo(previousPlainText, 0);
                }
                else
                {
                    await outputStream.WriteAsync(xoredBlock, 0, xoredBlock.Length, cancellationToken);
                    xoredBlock.CopyTo(previousPlainText, 0);
                }

                buffer.CopyTo(previousCiphertext, 0);
            }
        }
    }
    public void Encrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            byte[] buffer = new byte[blockSize];
            byte[] previousPlainText = new byte[blockSize];
            byte[] previousCiphertext = _iv;
            
            long totalBytes = inputStream.Length;
            long bytesProcessed = 0;
            
            Array.Clear(previousPlainText, 0, blockSize);
            while (bytesProcessed < totalBytes)
            {
                int bytesRead = inputStream.Read(buffer, 0, blockSize);
                bytesProcessed += bytesRead;
                byte[] currentPlaintext;

                if (bytesRead < blockSize)
                {
                    byte[] lastBlock = new byte[bytesRead];
                    Array.Copy(buffer, lastBlock, bytesRead);
                    currentPlaintext = padding.ApplyPadding(lastBlock, blockSize);
                }
                else
                {
                    currentPlaintext = (byte[])buffer.Clone();
                }
                byte[] xoredResult =  BitFunctions.XorBlocks(previousPlainText, previousCiphertext, blockSize);
                byte[] xoredBlock = BitFunctions.XorBlocks(currentPlaintext, xoredResult, blockSize);
                byte[] encryptedBlock = cipher.Encrypt(xoredBlock);
                outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
                currentPlaintext.CopyTo(previousPlainText, 0);
                encryptedBlock.CopyTo(previousCiphertext, 0);
            }

            if (bytesProcessed == 0 || bytesProcessed % blockSize == 0)
            {
                byte[] emptyBlock = new byte[0];
                byte[] paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
                byte[] xorResult = BitFunctions.XorBlocks(previousPlainText, previousCiphertext, blockSize);
                byte[] xoredBlock = BitFunctions.XorBlocks(paddedBlock, xorResult, blockSize);
                byte[] encryptedBlock = cipher.Encrypt(xoredBlock);
                outputStream.Write(encryptedBlock, 0, encryptedBlock.Length);
            }
        }
    }

   public void Decrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
{
    int blockSize = cipher.GetBlockSize();
    if (_iv.Length != blockSize)
    {
        throw new ArgumentException("IV size must be the same as block size.");
    }
    
    using (FileStream inputStream = File.OpenRead(input))
    using (FileStream outputStream = File.Create(output))
    {
        byte[] buffer = new byte[blockSize];
        byte[] previousPlainText = new byte[blockSize];
        byte[] previousCiphertext = (byte[])_iv.Clone();
        
        long totalBytes = inputStream.Length;
        long bytesProcessed = 0;
        
        Array.Clear(previousPlainText, 0, blockSize);
        
        if (totalBytes % blockSize != 0)
        {
            throw new InvalidOperationException("The file size must be a multiple of the block size.");
        }
        
        long totalBlocks = totalBytes / blockSize;
        long currentBlock = 0;
        
        while (bytesProcessed < totalBytes)
        {
            currentBlock++;
            int bytesRead = inputStream.Read(buffer, 0, blockSize);
            bytesProcessed += bytesRead;
            
            if (bytesRead != blockSize)
            {
                throw new InvalidOperationException("Error while reading file");
            }
            
            byte[] currentCiphertext = (byte[])buffer.Clone();
            byte[] decryptedBlock = cipher.Decrypt(buffer);
            
            byte[] xorResult = BitFunctions.XorBlocks(previousPlainText, previousCiphertext, blockSize);
            byte[] xoredBlock = BitFunctions.XorBlocks(decryptedBlock, xorResult, blockSize);
            
            if (currentBlock == totalBlocks)
            {
                byte[] unpadded = padding.RemovePadding(xoredBlock, blockSize);
                if (unpadded.Length > 0)
                {
                    outputStream.Write(unpadded, 0, unpadded.Length);
                }
            }
            else
            {
                outputStream.Write(xoredBlock, 0, xoredBlock.Length);
            }
            if (currentBlock == totalBlocks)
            {
                xoredBlock.CopyTo(previousPlainText, 0);
            }
            else
            {
                xoredBlock.CopyTo(previousPlainText, 0);
            }
            
            currentCiphertext.CopyTo(previousCiphertext, 0);
        }
    }
}
    public CipherMode Mode => CipherMode.PCBC;
}

public class CFBFileCipherMode : IFileCipherMode
{
    
    public async Task EncryptAsync(ISymmetricCipher cipher, IPadding padding, string input,
        string output, byte[] _iv, CancellationToken cancellationToken = default)
    {
       int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            byte[] shiftRegister = new byte[blockSize];
            Array.Copy(_iv, shiftRegister, blockSize);
            
            byte[] buffer = new byte[blockSize];
            long totalBytes = inputStream.Length;
            long bytesProcessed = 0;
            
            while (bytesProcessed < totalBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                int bytesRead = await inputStream.ReadAsync(buffer, 0, blockSize, cancellationToken);
                bytesProcessed += bytesRead;
                
                byte[] currentBlock;
                if (bytesRead < blockSize)
                {
                    byte[] lastBlock = new byte[bytesRead];
                    Array.Copy(buffer, lastBlock, bytesRead);
                    currentBlock = padding.ApplyPadding(lastBlock, blockSize);
                }
                else
                {
                    currentBlock = (byte[])buffer.Clone();
                }
                
                byte[] encryptedRegister = cipher.Encrypt(shiftRegister);
                
                byte[] xoredBlock = BitFunctions.XorBlocks(currentBlock, encryptedRegister, blockSize);
                
                await outputStream.WriteAsync(xoredBlock, 0, blockSize, cancellationToken);
                
                Array.Copy(xoredBlock, shiftRegister, blockSize);
            }
            
            if (bytesProcessed == 0 || bytesProcessed % blockSize == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                byte[] emptyBlock = new byte[0];
                byte[] paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
                
                byte[] encryptedRegister = cipher.Encrypt(shiftRegister);
                byte[] xoredBlock = BitFunctions.XorBlocks(paddedBlock, encryptedRegister, blockSize);
                await outputStream.WriteAsync(xoredBlock, 0, blockSize, cancellationToken);
            }
        }
    }

    public async Task DecryptAsync(ISymmetricCipher cipher, IPadding padding, string input,
        string output, byte[] _iv, CancellationToken cancellationToken = default)
    {
        int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            long totalBytes = inputStream.Length;
            
            if (totalBytes == 0)
            {
                throw new ArgumentException("Encrypted file cannot be empty");
            }
            
            if (totalBytes % blockSize != 0)
            {
                throw new ArgumentException(
                    "The file size must be a multiple of the block size. The file may be corrupted");
            }
            
            byte[] shiftRegister = new byte[blockSize];
            Array.Copy(_iv, shiftRegister, blockSize);
            
            byte[] buffer = new byte[blockSize];
            long totalBlocks = totalBytes / blockSize;
            long currentBlock = 0;
            long bytesRead = 0;
            
            while (bytesRead < totalBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                currentBlock++;
                int read = await inputStream.ReadAsync(buffer, 0, blockSize, cancellationToken);
                bytesRead += read;
                
                if (read != blockSize)
                {
                    throw new InvalidOperationException("Error while reading file");
                }
                
                byte[] ciphertext = new byte[blockSize];
                Array.Copy(buffer, ciphertext, blockSize);
                
                byte[] encryptedRegister = cipher.Encrypt(shiftRegister);
                
                byte[] xoredBlock = BitFunctions.XorBlocks(buffer, encryptedRegister, blockSize);
                
                if (currentBlock == totalBlocks)
                {
                    byte[] unpadded = padding.RemovePadding(xoredBlock, blockSize);
                    
                    if (unpadded.Length > 0)
                    {
                        await outputStream.WriteAsync(unpadded, 0, unpadded.Length, cancellationToken);
                    }
                }
                else
                {
                    await outputStream.WriteAsync(xoredBlock, 0, blockSize, cancellationToken);
                }
                
                Array.Copy(ciphertext, shiftRegister, blockSize);
            }
        }
    }
    
    public void Encrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            byte[] shiftRegister = new byte[blockSize];
            Array.Copy(_iv, shiftRegister, blockSize);
            
            byte[] buffer = new byte[blockSize];
            long totalBytes = inputStream.Length;
            long bytesProcessed = 0;
            
            while (bytesProcessed < totalBytes)
            {
                int bytesRead = inputStream.Read(buffer, 0, blockSize);
                bytesProcessed += bytesRead;
                
                byte[] currentBlock;
                if (bytesRead < blockSize)
                {
                    byte[] lastBlock = new byte[bytesRead];
                    Array.Copy(buffer, lastBlock, bytesRead);
                    currentBlock = padding.ApplyPadding(lastBlock, blockSize);
                }
                else
                {
                    currentBlock = (byte[])buffer.Clone();
                }
                
                byte[] encryptedRegister = cipher.Encrypt(shiftRegister);
                
                byte[] xoredBlock = BitFunctions.XorBlocks(currentBlock, encryptedRegister, blockSize);
                
                outputStream.Write(xoredBlock, 0, blockSize);
                
                Array.Copy(xoredBlock, shiftRegister, blockSize);
            }
            
            if (bytesProcessed == 0 || bytesProcessed % blockSize == 0)
            {
                byte[] emptyBlock = new byte[0];
                byte[] paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
                
                byte[] encryptedRegister = cipher.Encrypt(shiftRegister);
                byte[] xoredBlock = BitFunctions.XorBlocks(paddedBlock, encryptedRegister, blockSize);
                outputStream.Write(xoredBlock, 0, blockSize);
            }
        }
    }

    public void Decrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            long totalBytes = inputStream.Length;
            if (totalBytes == 0)
            {
                throw new ArgumentException("Encrypted file cannot be empty");
            }
            
            if (totalBytes % blockSize != 0)
            {
                throw new ArgumentException(
                    "The file size must be a multiple of the block size. The file may be corrupted");
            }
            
            byte[] shiftRegister = new byte[blockSize];
            Array.Copy(_iv, shiftRegister, blockSize);
            
            byte[] buffer = new byte[blockSize];
            long totalBlocks = totalBytes / blockSize;
            long currentBlock = 0;
            long bytesRead = 0;
            
            while (bytesRead < totalBytes)
            {
                currentBlock++;
                int read = inputStream.Read(buffer, 0, blockSize);
                bytesRead += read;
                
                if (read != blockSize)
                {
                    throw new InvalidOperationException("Error while reading file");
                }
                
                byte[] ciphertext = new byte[blockSize];
                Array.Copy(buffer, ciphertext, blockSize);
                
                byte[] encryptedRegister = cipher.Encrypt(shiftRegister);
                
                byte[] xoredBlock = BitFunctions.XorBlocks(buffer, encryptedRegister, blockSize);
                
                if (currentBlock == totalBlocks)
                {
                    byte[] unpadded = padding.RemovePadding(xoredBlock, blockSize);
                    if (unpadded.Length > 0)
                    {
                        outputStream.Write(unpadded, 0, unpadded.Length);
                    }
                }
                else
                {
                    outputStream.Write(xoredBlock, 0, blockSize);
                }
                
                Array.Copy(ciphertext, shiftRegister, blockSize);
            }
        }
    }
    
    public CipherMode Mode => CipherMode.CFB;
}


public class OFBFileCipherMode : IFileCipherMode
{
    
    public async Task EncryptAsync(ISymmetricCipher cipher, IPadding padding, string input,
        string output, byte[] _iv, CancellationToken cancellationToken = default)
    {
        int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            byte[] keyStream = new byte[blockSize];
            Array.Copy(_iv, keyStream, blockSize);
            
            byte[] buffer = new byte[blockSize];
            long totalBytes = inputStream.Length;
            long bytesProcessed = 0;
            
            while (bytesProcessed < totalBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                int bytesRead = await inputStream.ReadAsync(buffer, 0, blockSize, cancellationToken);
                bytesProcessed += bytesRead;
                
                byte[] currentBlock;
                if (bytesRead < blockSize)
                {
                    byte[] lastBlock = new byte[bytesRead];
                    Array.Copy(buffer, lastBlock, bytesRead);
                    currentBlock = padding.ApplyPadding(lastBlock, blockSize);
                }
                else
                {
                    currentBlock = (byte[])buffer.Clone();
                }
                
                byte[] newKeyStream = cipher.Encrypt(keyStream);
                
                byte[] xoredBlock = BitFunctions.XorBlocks(currentBlock, newKeyStream, blockSize);
                
                await outputStream.WriteAsync(xoredBlock, 0, blockSize, cancellationToken);
                
                Array.Copy(newKeyStream, keyStream, blockSize);
            }
            
            if (bytesProcessed == 0 || bytesProcessed % blockSize == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                byte[] emptyBlock = new byte[0];
                byte[] paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
                
                byte[] newKeyStream = cipher.Encrypt(keyStream);
                byte[] xoredBlock = BitFunctions.XorBlocks(paddedBlock, newKeyStream, blockSize);
                await outputStream.WriteAsync(xoredBlock, 0, blockSize, cancellationToken);
            }
        }
    }

    
    public async Task DecryptAsync(ISymmetricCipher cipher, IPadding padding, string input,
        string output, byte[] _iv, CancellationToken cancellationToken = default)
    {
         int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            long totalBytes = inputStream.Length;
            
            if (totalBytes == 0)
            {
                throw new ArgumentException("Encrypted file cannot be empty");
            }
            
            if (totalBytes % blockSize != 0)
            {
                throw new ArgumentException(
                    "The file size must be a multiple of the block size. The file may be corrupted");
            }
            
            byte[] keyStream = new byte[blockSize];
            Array.Copy(_iv, keyStream, blockSize);
            
            byte[] buffer = new byte[blockSize];
            long totalBlocks = totalBytes / blockSize;
            long currentBlock = 0;
            long bytesRead = 0;
            
            while (bytesRead < totalBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                currentBlock++;
                int read = await inputStream.ReadAsync(buffer, 0, blockSize, cancellationToken);
                bytesRead += read;
                
                if (read != blockSize)
                {
                    throw new InvalidOperationException("Error while reading file");
                }
                
                byte[] newKeyStream = cipher.Encrypt(keyStream);
                
                byte[] xoredBlock = BitFunctions.XorBlocks(buffer, newKeyStream, blockSize);
                
                if (currentBlock == totalBlocks)
                {
                    byte[] unpadded = padding.RemovePadding(xoredBlock, blockSize);
                    
                    if (unpadded.Length > 0)
                    {
                        await outputStream.WriteAsync(unpadded, 0, unpadded.Length, cancellationToken);
                    }
                }
                else
                {
                    await outputStream.WriteAsync(xoredBlock, 0, blockSize, cancellationToken);
                }
                
                Array.Copy(newKeyStream, keyStream, blockSize);
            }
        }
    }
    
    public void Encrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            byte[] keyStream = new byte[blockSize];
            Array.Copy(_iv, keyStream, blockSize);
            
            byte[] buffer = new byte[blockSize];
            long totalBytes = inputStream.Length;
            long bytesProcessed = 0;
            
            while (bytesProcessed < totalBytes)
            {
                int bytesRead = inputStream.Read(buffer, 0, blockSize);
                bytesProcessed += bytesRead;
                
                byte[] currentBlock;
                if (bytesRead < blockSize)
                {
                    byte[] lastBlock = new byte[bytesRead];
                    Array.Copy(buffer, lastBlock, bytesRead);
                    currentBlock = padding.ApplyPadding(lastBlock, blockSize);
                }
                else
                {
                    currentBlock = (byte[])buffer.Clone();
                }
                
                byte[] newKeyStream = cipher.Encrypt(keyStream);
                
                byte[] xoredBlock = BitFunctions.XorBlocks(currentBlock, newKeyStream, blockSize);
                
                outputStream.Write(xoredBlock, 0, blockSize);
                
                Array.Copy(newKeyStream, keyStream, blockSize);
            }
            
            if (bytesProcessed == 0 || bytesProcessed % blockSize == 0)
            {
                byte[] emptyBlock = new byte[0];
                byte[] paddedBlock = padding.ApplyPadding(emptyBlock, blockSize);
                
                byte[] newKeyStream = cipher.Encrypt(keyStream);
                byte[] xoredBlock = BitFunctions.XorBlocks(paddedBlock, newKeyStream, blockSize);
                outputStream.Write(xoredBlock, 0, blockSize);
            }
        }
    }

    public void Decrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            long totalBytes = inputStream.Length;
            if (totalBytes == 0)
            {
                throw new ArgumentException("Encrypted file cannot be empty");
            }
            
            if (totalBytes % blockSize != 0)
            {
                throw new ArgumentException(
                    "The file size must be a multiple of the block size. The file may be corrupted");
            }
            
            byte[] keyStream = new byte[blockSize];
            Array.Copy(_iv, keyStream, blockSize);
            
            byte[] buffer = new byte[blockSize];
            long totalBlocks = totalBytes / blockSize;
            long currentBlock = 0;
            long bytesRead = 0;
            
            while (bytesRead < totalBytes)
            {
                currentBlock++;
                int read = inputStream.Read(buffer, 0, blockSize);
                bytesRead += read;
                
                if (read != blockSize)
                {
                    throw new InvalidOperationException("Error while reading file");
                }
                
                byte[] newKeyStream = cipher.Encrypt(keyStream);
                
                byte[] xoredBlock = BitFunctions.XorBlocks(buffer, newKeyStream, blockSize);
                
                if (currentBlock == totalBlocks)
                {
                    byte[] unpadded = padding.RemovePadding(xoredBlock, blockSize);
                    if (unpadded.Length > 0)
                    {
                        outputStream.Write(unpadded, 0, unpadded.Length);
                    }
                }
                else
                {
                    outputStream.Write(xoredBlock, 0, blockSize);
                }
                
                Array.Copy(newKeyStream, keyStream, blockSize);
            }
        }
    }
    
    public CipherMode Mode => CipherMode.OFB;
}
public class CTRFileCipherMode : IFileCipherMode
{
    public async Task EncryptAsync(
        ISymmetricCipher cipher,
        IPadding padding,
        string input,
        string output,
        byte[] _iv,
        CancellationToken cancellationToken = default)
    {
        int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }

        const int BatchBlocks = 512;                
        int batchBytes = BatchBlocks * blockSize;

        await using var inputStream = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);
        await using var outputStream = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);

        byte[] readBuffer = new byte[batchBytes];
        byte[] carry = new byte[blockSize];         
        int carryLen = 0;

        long blockIndexBase = 0;                    

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int read = await inputStream.ReadAsync(readBuffer, 0, readBuffer.Length, cancellationToken);
            if (read == 0 && carryLen == 0)
            {
                break;
            }
            
            int chunkLen = carryLen + read;
            
            byte[] chunk = new byte[chunkLen];
            if (carryLen > 0)
            {
                Buffer.BlockCopy(carry, 0, chunk, 0, carryLen);
            }
            if (read > 0)
            {
                Buffer.BlockCopy(readBuffer, 0, chunk, carryLen, read);
            }

            int fullBlocks = chunkLen / blockSize;
            int tail = chunkLen % blockSize;

            carryLen = tail;
            if (tail > 0)
            {
                Buffer.BlockCopy(chunk, fullBlocks * blockSize, carry, 0, tail);
            }

            if (fullBlocks == 0)
            {
                if (read == 0)
                {
                    break;
                }
                continue;
            }

            byte[] outChunk = new byte[fullBlocks * blockSize];

            Parallel.For(0, fullBlocks, i =>
            {
                int offset = i * blockSize;

                byte[] counter = (byte[])_iv.Clone();
                AddToCounter(counter, blockIndexBase + i);

                byte[] ks = cipher.Encrypt(counter);

                for (int j = 0; j < blockSize; j++)
                {
                    outChunk[offset + j] = (byte)(chunk[offset + j] ^ ks[j]);
                }
            });

            await outputStream.WriteAsync(outChunk, 0, outChunk.Length, cancellationToken);
            blockIndexBase += fullBlocks;

            if (read == 0)
                break;
        }

        if (carryLen > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            byte[] counter = (byte[])_iv.Clone();
            AddToCounter(counter, blockIndexBase);

            byte[] ks = cipher.Encrypt(counter);

            byte[] lastOut = new byte[carryLen];
            for (int i = 0; i < carryLen; i++)
                lastOut[i] = (byte)(carry[i] ^ ks[i]);

            await outputStream.WriteAsync(lastOut, 0, lastOut.Length, cancellationToken);
        }
    }

    public async Task DecryptAsync(
        ISymmetricCipher cipher,
        IPadding padding,
        string input,
        string output,
        byte[] _iv,
        CancellationToken cancellationToken = default)
    {
        await EncryptAsync(cipher, padding, input, output, _iv, cancellationToken);
    }

    private static void AddToCounter(byte[] counter, long value)
    {
        long carry = value;
        for (int i = counter.Length - 1; i >= 0 && carry != 0; i--)
        {
            long sum = counter[i] + (carry & 0xFF);
            counter[i] = (byte)sum;
            carry = (carry >> 8) + (sum >> 8);
        }
    }
    
    private void IncrementCounter(byte[] counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }
    
    public void Encrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        int blockSize = cipher.GetBlockSize();
        if (_iv.Length != blockSize)
        {
            throw new ArgumentException("IV size must be the same as block size.");
        }
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            byte[] counter = new byte[blockSize];
            Array.Copy(_iv, counter, blockSize);
            
            byte[] buffer = new byte[blockSize];
            
            int bytesRead;
            while ((bytesRead = inputStream.Read(buffer, 0, blockSize)) > 0)
            {
                byte[] encryptedCounter = cipher.Encrypt(counter);
                
                for (int i = 0; i < bytesRead; i++)
                {
                    buffer[i] ^= encryptedCounter[i];
                }
                
                outputStream.Write(buffer, 0, bytesRead); 
                IncrementCounter(counter);
            }
        }
    }

    public void Decrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        Encrypt(cipher, padding, input, output, _iv);
    }
    
    public CipherMode Mode => CipherMode.CTR;
}


public class RandomDeltaFileCipherMode : IFileCipherMode
{
    private readonly Random _random = new Random();
    
    public async Task EncryptAsync(ISymmetricCipher cipher, IPadding padding, string input,
        string output, byte[] _iv, CancellationToken cancellationToken = default)
    {
        int blockSize = cipher.GetBlockSize();
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            long fileSize = inputStream.Length;
            long totalBlocks = (fileSize + blockSize - 1) / blockSize;
            
            byte[] blockCountBytes = BitConverter.GetBytes(totalBlocks);
            await outputStream.WriteAsync(blockCountBytes, 0, 8, cancellationToken);
            
            List<byte[]> deltas = new List<byte[]>();
            for (int i = 0; i < totalBlocks; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                byte[] delta = new byte[blockSize];
                _random.NextBytes(delta);
                deltas.Add(delta);
                await outputStream.WriteAsync(delta, 0, blockSize, cancellationToken);
            }
            
            inputStream.Position = 0;
            
            byte[] buffer = new byte[blockSize];
            int deltaIndex = 0;
            int bytesRead;
            
            while ((bytesRead = await inputStream.ReadAsync(buffer, 0, blockSize, cancellationToken)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                byte[] blockToProcess;
                
                if (bytesRead < blockSize)
                {
                    byte[] lastBlock = new byte[bytesRead];
                    Array.Copy(buffer, lastBlock, bytesRead);
                    blockToProcess = padding.ApplyPadding(lastBlock, blockSize);
                }
                else
                {
                    blockToProcess = (byte[])buffer.Clone();
                }
                
                byte[] delta = deltas[deltaIndex++];
                byte[] xored = BitFunctions.XorBlocks(blockToProcess, delta, blockSize);
                byte[] encrypted = cipher.Encrypt(xored);
                await outputStream.WriteAsync(encrypted, 0, blockSize, cancellationToken);
            }
        }
    }

    public async Task DecryptAsync(ISymmetricCipher cipher, IPadding padding, string input,
        string output, byte[] _iv, CancellationToken cancellationToken = default)
    {
        var blockSize = cipher.GetBlockSize();
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            var blockCountBytes = new byte[8];
            await inputStream.ReadAsync(blockCountBytes, 0, 8, cancellationToken);
            var totalBlocks = BitConverter.ToInt64(blockCountBytes, 0);
            
            var deltas = new List<byte[]>();
            for (var i = 0; i < totalBlocks; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var delta = new byte[blockSize];
                await inputStream.ReadAsync(delta, 0, blockSize, cancellationToken);
                deltas.Add(delta);
            }
            
            var buffer = new byte[blockSize];
            var deltaIndex = 0;
            int bytesRead;
            long currentBlock = 0;
            
            while ((bytesRead = await inputStream.ReadAsync(buffer, 0, blockSize, cancellationToken)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                currentBlock++;
                
                if (bytesRead != blockSize)
                {
                    throw new InvalidOperationException("Invalid block size in encrypted file");
                }
                
                var decrypted = cipher.Decrypt(buffer);
                var delta = deltas[deltaIndex++];
                var xored = BitFunctions.XorBlocks(decrypted, delta, blockSize);
                
                if (currentBlock == totalBlocks)
                {
                    var unpadded = padding.RemovePadding(xored, blockSize);
                    if (unpadded.Length > 0)
                    {
                        await outputStream.WriteAsync(unpadded, 0, unpadded.Length, cancellationToken);
                    }
                }
                else
                {
                    await outputStream.WriteAsync(xored, 0, blockSize, cancellationToken);
                }
            }
        }
    }
    
    public void Encrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        int blockSize = cipher.GetBlockSize();
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            var fileSize = inputStream.Length;
            var totalBlocks = (fileSize + blockSize - 1) / blockSize;
            
            var blockCountBytes = BitConverter.GetBytes(totalBlocks);
            outputStream.Write(blockCountBytes, 0, 8);
            
            var deltas = new List<byte[]>();
            for (var i = 0; i < totalBlocks; i++)
            {
                var delta = new byte[blockSize];
                _random.NextBytes(delta);
                deltas.Add(delta);
                outputStream.Write(delta, 0, blockSize);
            }
            
            inputStream.Position = 0;
            var buffer = new byte[blockSize];
            var deltaIndex = 0;
            int bytesRead;
            
            while ((bytesRead = inputStream.Read(buffer, 0, blockSize)) > 0)
            {
                byte[] blockToProcess;
                if (bytesRead < blockSize)
                {
                    var lastBlock = new byte[bytesRead];
                    Array.Copy(buffer, lastBlock, bytesRead);
                    blockToProcess = padding.ApplyPadding(lastBlock, blockSize);
                }
                else
                {
                    blockToProcess = (byte[])buffer.Clone();
                }
                
                var delta = deltas[deltaIndex++];
                var xored = BitFunctions.XorBlocks(blockToProcess, delta, blockSize);
                var encrypted = cipher.Encrypt(xored);
                outputStream.Write(encrypted, 0, blockSize);
            }
        }
    }

    public void Decrypt(ISymmetricCipher cipher, IPadding padding, string input, string output, byte[] _iv)
    {
        var blockSize = cipher.GetBlockSize();
        
        using (FileStream inputStream = File.OpenRead(input))
        using (FileStream outputStream = File.Create(output))
        {
            byte[] blockCountBytes = new byte[8];
            
            inputStream.Read(blockCountBytes, 0, 8);
            
            var totalBlocks = BitConverter.ToInt64(blockCountBytes, 0);
            
            var deltas = new List<byte[]>();
            
            for (var i = 0; i < totalBlocks; i++)
            {
                var delta = new byte[blockSize];
                inputStream.Read(delta, 0, blockSize);
                deltas.Add(delta);
            }
            
            var buffer = new byte[blockSize];
            var deltaIndex = 0;
            int bytesRead;
            long currentBlock = 0;
            
            while ((bytesRead = inputStream.Read(buffer, 0, blockSize)) > 0)
            {
                currentBlock++;
                
                if (bytesRead != blockSize)
                {
                    throw new InvalidOperationException("Invalid block size in encrypted file");
                }
                
                var decrypted = cipher.Decrypt(buffer);
                var delta = deltas[deltaIndex++];
                var xored = BitFunctions.XorBlocks(decrypted, delta, blockSize);
                
                if (currentBlock == totalBlocks)
                {
                    var unpadded = padding.RemovePadding(xored, blockSize);
                    if (unpadded.Length > 0)
                    {
                        outputStream.Write(unpadded, 0, unpadded.Length);
                    }
                }
                else
                {
                    outputStream.Write(xored, 0, blockSize);
                }
            }
        }
    }
    
    public CipherMode Mode => CipherMode.RandomDelta;
}


public static class FileCipherModeFactory
{
    public static IFileCipherMode Create(CipherMode mode)
    {
        return mode switch
        {
            CipherMode.ECB => new ECBFileCipherMode(),
            CipherMode.CBC => new CBCFileCipherMode(),
            CipherMode.PCBC => new PCBCFileCipherMode(),
            CipherMode.CFB => new CFBFileCipherMode(),
            CipherMode.OFB => new OFBFileCipherMode(),
            CipherMode.CTR => new CTRFileCipherMode(),
            CipherMode.RandomDelta => new RandomDeltaFileCipherMode(),
            _ => throw new ArgumentException($"Unsupported cipher mode: {mode}", nameof(mode))
        };
    }
}
