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
    public static class PgpEncryptBlob
    {
        private static string PublicKeyEnvironmentVariable = "pgp_public_key";

        [FunctionName("PgpEncryptBlob")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");
            string publicKeyBase64 = Environment.GetEnvironmentVariable(PublicKeyEnvironmentVariable);

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

            BlobContainerClient inputContainer = new BlobContainerClient(storageConnectionString, containerName);
            BlobClient blobClient = inputContainer.GetBlobClient(blobPath);

            // Create a memory stream and download the blob into the stream
            using var ms = new MemoryStream();
            await blobClient.DownloadToAsync(ms);

            byte[] publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            string publicKey = Encoding.UTF8.GetString(publicKeyBytes);

            Stream encryptedData = await EncryptAsync(ms, publicKey);

            string encryptedPath = blobPath + ".pgp";
            await inputContainer.UploadBlobAsync(encryptedPath, encryptedData);

            string responseMessage = "encrypted";

            return new OkObjectResult(responseMessage);
        }

            private static async Task<Stream> EncryptAsync(Stream inputStream, string publicKey)
        {
            using (PGP pgp = new PGP())
            {
                Stream outputStream = new MemoryStream();

                using (inputStream)
                using (Stream publicKeyStream = GenerateStreamFromString(publicKey))
                {
                    await pgp.EncryptStreamAsync(inputStream, outputStream, publicKeyStream, true, true);
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
