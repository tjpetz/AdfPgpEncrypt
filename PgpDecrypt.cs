/*
 *  Azure Function to be used in ADF pipelines to PGP decrypt a blob.
 *
 *  Derived from http://github.com/lfalck/AzureFunctionsPGPDecrypt
*/

using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using PgpCore;
using Azure.Storage.Blobs;
using System.Text;

namespace tjpetz.adfpgpfunctions
{
    public static class PgpDecryptBlob
    {
        private static string PrivateKeyEnvironmentVariable = "pgp_private_key";
        private static string PrivateKeyPassPhraseVariable = "pgp_pass_phrase";

        [FunctionName("PgpDecryptBlob")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");
            string privateKeyBase64 = Environment.GetEnvironmentVariable(PrivateKeyEnvironmentVariable);
            string passPhrase = Environment.GetEnvironmentVariable(PrivateKeyPassPhraseVariable);

            string storageConnectionString = req.Query["storageConnectionString"];
            string containerName = req.Query["containerName"];
            string blobPath = req.Query["blobPath"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            storageConnectionString = storageConnectionString ?? data?.storageConnectionString;
            containerName = containerName ?? data?.containerName;
            blobPath = blobPath ?? data?.blobPath;

            log.LogInformation($"storageConnectionString = {storageConnectionString}");
            log.LogInformation($"container = {containerName}");
            log.LogInformation($"path = {blobPath}");

            byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
            string privateKey = Encoding.UTF8.GetString(privateKeyBytes);

            BlobContainerClient inputContainer = new BlobContainerClient(storageConnectionString, containerName);
            BlobClient blobClient = inputContainer.GetBlobClient(blobPath);

            // Create a memory stream and download the blob into the stream
            using var ms = new MemoryStream();
            await blobClient.DownloadToAsync(ms);
            ms.Seek(0, SeekOrigin.Begin);

            Stream decryptedData = await DecryptAsync(ms, privateKey, passPhrase);

            // If the file ends in .pgp remove it otherwise we'll add .decrypted as the extension
            string decryptedPath = "";
            if (blobPath.EndsWith(".pgp")) {
                decryptedPath = blobPath.Substring(0, blobPath.Length - 4);
            } else {
                decryptedPath = blobPath + ".decrypted";
            }
            await inputContainer.UploadBlobAsync(decryptedPath, decryptedData);

            string responseMessage = "decrypted";

            return new OkObjectResult(responseMessage);
        }

        private static async Task<Stream> DecryptAsync(Stream inputStream, string privateKey, string passPhrase)
        {
            using (PGP pgp = new PGP())
            {
                Stream outputStream = new MemoryStream();

                using (inputStream)
                using (Stream privateKeyStream = GenerateStreamFromString(privateKey))
                {
                    await pgp.DecryptStreamAsync(inputStream, outputStream, privateKeyStream, passPhrase);
                    outputStream.Seek(0, SeekOrigin.Begin);
                    return outputStream;
                }
            }
        }

        private static Stream GenerateStreamFromString(string s)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

    }
}
