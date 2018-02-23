namespace Microsoft.ApplicationInsights.WindowsServer
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net.Http;
    using System.Runtime.Serialization.Json;
    using System.Text;
    using System.Net;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ApplicationInsights.WindowsServer.Implementation;
    using Microsoft.ApplicationInsights.WindowsServer.Implementation.DataContracts;
    using Microsoft.ApplicationInsights.WindowsServer.Mock;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Assert = Xunit.Assert;

    [TestClass]
    public class AzureInstanceMetadataTests
    {
        [TestMethod]
        public void GetAzureInstanceMetadataFieldsAsExpected()
        {
            HeartbeatProviderMock hbeatMock = new HeartbeatProviderMock();
            AzureInstanceMetadataRequestMock azureInstanceRequestorMock = new AzureInstanceMetadataRequestMock();
            AzureHeartbeatProperties azureIMSFields = new AzureHeartbeatProperties(azureInstanceRequestorMock, true);

            var taskWaiter = azureIMSFields.SetDefaultPayload(new string[] { }, hbeatMock).ConfigureAwait(false);
            Assert.True(taskWaiter.GetAwaiter().GetResult()); // no await for tests

            foreach (string fieldName in azureIMSFields.ExpectedAzureImsFields)
            {
                string expectedFieldName = string.Concat(AzureHeartbeatProperties.HeartbeatPropertyPrefix, fieldName);
                Assert.True(hbeatMock.HbeatProps.ContainsKey(expectedFieldName));
                Assert.False(string.IsNullOrEmpty(hbeatMock.HbeatProps[expectedFieldName]));
            }
        }

        [TestMethod]
        public void FailToObtainAzureInstanceMetadataFieldsAltogether()
        {
            HeartbeatProviderMock hbeatMock = new HeartbeatProviderMock();
            AzureInstanceMetadataRequestMock azureInstanceRequestorMock = new AzureInstanceMetadataRequestMock(
                getComputeMetadata: () =>
                {
                    try
                    {
                        throw new System.Exception("Failure");
                    }
                    catch
                    {
                    }

                    return null;
                });
            var azureIMSFields = new AzureHeartbeatProperties(azureInstanceRequestorMock, true);
            var defaultFields = azureIMSFields.ExpectedAzureImsFields;

            // not adding the fields we're looking for, simulation of the Azure Instance Metadata service not being present...
            var taskWaiter = azureIMSFields.SetDefaultPayload(new string[] { }, hbeatMock).ConfigureAwait(false);
            Assert.False(taskWaiter.GetAwaiter().GetResult()); // nop await for tests

            foreach (string fieldName in defaultFields)
            {
                string heartbeatFieldName = string.Concat(AzureHeartbeatProperties.HeartbeatPropertyPrefix, fieldName);
                Assert.False(hbeatMock.HbeatProps.ContainsKey(heartbeatFieldName));
            }
        }

        [TestMethod]
        public void AzureInstanceMetadataObtainedSuccessfully()
        {
            AzureInstanceComputeMetadata expected = new AzureInstanceComputeMetadata()
            {
                Location = "US-West",
                Name = "test-vm01",
                Offer = "D9_USWest",
                OsType = "Linux",
                PlatformFaultDomain = "0",
                PlatformUpdateDomain = "0",
                Publisher = "Microsoft",
                ResourceGroupName = "test.resource-group_01",
                Sku = "Windows_10",
                SubscriptionId = Guid.NewGuid().ToString(),
                Version = "10.8a",
                VmId = Guid.NewGuid().ToString(),
                VmSize = "A8"
            };

            HeartbeatProviderMock hbeatMock = new HeartbeatProviderMock();
            AzureInstanceMetadataRequestMock azureInstanceRequestorMock = new AzureInstanceMetadataRequestMock(
                getComputeMetadata: () =>
                {
                    return expected;
                });
            var azureIMSFields = new AzureHeartbeatProperties(azureInstanceRequestorMock, true);
            var defaultFields = azureIMSFields.ExpectedAzureImsFields;

            // not adding the fields we're looking for, simulation of the Azure Instance Metadata service not being present...
            var taskWaiter = azureIMSFields.SetDefaultPayload(new string[] { }, hbeatMock).ConfigureAwait(false);
            Assert.True(taskWaiter.GetAwaiter().GetResult()); // nop await for tests

            foreach (string fieldName in defaultFields)
            {
                string heartbeatFieldName = string.Concat(AzureHeartbeatProperties.HeartbeatPropertyPrefix, fieldName);
                Assert.True(hbeatMock.HbeatProps.ContainsKey(heartbeatFieldName));
                Assert.Equal(expected.GetValueForField(fieldName), hbeatMock.HbeatProps[heartbeatFieldName]);
            }
        }

        [TestMethod]
        public void AzureIMSTestFieldGoodValueVerification()
        {
            // there are three fields we verify within the AzureInstanceComputeMetadata class, test the
            // verification routines
            AzureInstanceComputeMetadata md = new AzureInstanceComputeMetadata();

            List<string> acceptableNames = new List<string>
            {
                "acceptable-(Name)_Here",
                "A",
                "0123456789012345678901234567890123456789012345678901234567890123",
                "(should-work-fine)"
            };

            foreach (string goodName in acceptableNames)
            {
                md.Name = goodName;
                Assert.Equal(md.Name, md.VerifyExpectedValue("name"));
            }

            List<string> acceptableResourceGroupNames = new List<string>
            {
                "1",
                "acceptable_resourceGr0uP.Name-Here",
                "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-",
                "0123startsWithANumber"
            };

            foreach (string goodResourceGroupName in acceptableResourceGroupNames)
            {
                md.ResourceGroupName = goodResourceGroupName;
                Assert.Equal(md.ResourceGroupName, md.VerifyExpectedValue("resourceGroupName"));
            }

            var subId = Guid.NewGuid();
            List<string> acceptableSubscriptionIds = new List<string>
            {
                subId.ToString(),
                subId.ToString().ToLowerInvariant(),
                subId.ToString().ToUpperInvariant()
            };

            foreach (string goodSubscriptionId in acceptableSubscriptionIds)
            {
                md.SubscriptionId = goodSubscriptionId;
                Assert.Equal(md.SubscriptionId, md.VerifyExpectedValue("subscriptionId"));
            }
        }

        [TestMethod]
        public void AzureIMSTestFieldBadValuesFailVerification()
        {
            // there are three fields we verify within the AzureInstanceComputeMetadata class, test the
            // verification routines
            AzureInstanceComputeMetadata md = new AzureInstanceComputeMetadata();

            List<string> unacceptableNames = new List<string>
            {
                "unacceptable name spaces",
                "string-too-long-0123456789012345678901234567890123456789012345678901234567890123456789",
                "unacceptable=name+punctuation",
                string.Empty
            };

            foreach (string failName in unacceptableNames)
            {
                md.Name = failName;
                Assert.Empty(md.VerifyExpectedValue("name"));
            }

            List<string> unacceptableResourceGroupNames = new List<string>
            {
                "unacceptable name spaces",
                "string-too-long-012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                "unacceptable#punctuation!",
                "ends.with.a.period.",
                string.Empty
            };

            foreach (string failResGrpName in unacceptableResourceGroupNames)
            {
                md.ResourceGroupName = failResGrpName;
                Assert.Empty(md.VerifyExpectedValue("resourceGroupName"));
            }

            List<string> unacceptableSubscriptionIds = new List<string>
            {
                "unacceptable name not a guid",
                string.Empty
            };

            foreach (string failSubscriptionId in unacceptableSubscriptionIds)
            {
                md.SubscriptionId = failSubscriptionId;
                Assert.Empty(md.VerifyExpectedValue("subscriptionId"));
            }
        }

        [TestMethod]
        public void AzureIMSGetFieldByNameFailsWithException()
        {
            AzureInstanceComputeMetadata md = new AzureInstanceComputeMetadata();
            Assert.Throws(typeof(ArgumentOutOfRangeException), () => md.GetValueForField("not-a-field"));
        }

        [TestMethod]
        public void AzureIMSReturnsExpectedValuesForEachFieldAfterSerialization()
        {
            AzureInstanceComputeMetadata expectMetadata = new AzureInstanceComputeMetadata()
            {
                Location = "US-West",
                Name = "test-vm01",
                Offer = "D9_USWest",
                OsType = "Linux",
                PlatformFaultDomain = "0",
                PlatformUpdateDomain = "0",
                Publisher = "Microsoft",
                ResourceGroupName = "test.resource-group_01",
                Sku = "Windows_10",
                SubscriptionId = Guid.NewGuid().ToString(),
                Version = "10.8a",
                VmId = Guid.NewGuid().ToString(),
                VmSize = "A8"
            };

            DataContractJsonSerializer deserializer = new DataContractJsonSerializer(typeof(AzureInstanceComputeMetadata));

            // use the expected JSON field name style, uses camelCase...
            string jsonFormatString = 
@"{{ 
  ""osType"": ""{0}"",
  ""location"": ""{1}"",
  ""name"": ""{2}"",
  ""offer"": ""{3}"",
  ""platformFaultDomain"": ""{4}"",
  ""platformUpdateDomain"": ""{5}"",
  ""publisher"": ""{6}"",
  ""sku"": ""{7}"",
  ""version"": ""{8}"",
  ""vmId"": ""{9}"",
  ""vmSize"": ""{10}"",
  ""subscriptionId"": ""{11}"",
  ""resourceGroupName"": ""{12}""
}}";
            string json = string.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                jsonFormatString,
                expectMetadata.OsType,
                expectMetadata.Location,
                expectMetadata.Name,
                expectMetadata.Offer,
                expectMetadata.PlatformFaultDomain,
                expectMetadata.PlatformUpdateDomain,
                expectMetadata.Publisher,
                expectMetadata.Sku,
                expectMetadata.Version,
                expectMetadata.VmId,
                expectMetadata.VmSize,
                expectMetadata.SubscriptionId,
                expectMetadata.ResourceGroupName);

            var jsonBytes = Encoding.UTF8.GetBytes(json);
            MemoryStream jsonStream = new MemoryStream(jsonBytes, 0, jsonBytes.Length);

            AzureInstanceComputeMetadata compareMetadata = (AzureInstanceComputeMetadata)deserializer.ReadObject(jsonStream);

            AzureHeartbeatProperties heartbeatProps = new AzureHeartbeatProperties();
            foreach (string fieldName in heartbeatProps.ExpectedAzureImsFields)
            {
                Assert.Equal(expectMetadata.GetValueForField(fieldName), compareMetadata.GetValueForField(fieldName));
            }
        }

        [TestMethod]
        public void AzureIMSGetFailsWithException()
        {
            var requestor = new AzureMetadataRequestor(makeAzureIMSRequestor: (string uri) =>
            {
                throw new HttpRequestException("MaxResponseContentLength exceeded");
            });

            try
            {
                var result = requestor.GetAzureComputeMetadata();
                Assert.Null(result.GetAwaiter().GetResult());                
            }
            catch
            {
                Assert.True(false, "Expectation is that exceptions will be handled within AzureMetadataRequestor, not the calling code.");
            }
        }

        [TestMethod]
        public void SpoofedResponseFromAzureIMSDoesntCrash()
        {
            CancellationTokenSource cts = new CancellationTokenSource();

            //string mockUri = AzureMetadataRequestor.baseImdsUrl + "/"; //}?{AzureMetadataRequestor.imdsTextFormat}&{AzureMetadataRequestor.imdsApiVersion}";
            string mockUri = "http://localhost:9922/";

            using (new LocalServer(mockUri, (HttpListenerContext context) =>
            {
                HttpListenerResponse response = context.Response;

                // Construct a response.
                byte[] buffer = System.Text.Encoding.UTF8.GetBytes("Name1" + Environment.NewLine);
                response.ContentEncoding = System.Text.Encoding.UTF8;
                // Get a response stream and write the response to it.
                response.ContentLength64 = buffer.Length;
                System.IO.Stream output = response.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();

                context.Response.StatusCode = 200;
            }))
            {
                var azIms = new AzureMetadataRequestor();
                azIms.BaseAimsUri = mockUri;
                var fields = azIms.GetAzureInstanceMetadataComputeFields();
                fields.Wait();
                List<string> values = new List<string>();
                foreach (var iem in fields.Result)
                {
                    values.Add(iem);
                }
            }
        }

        class LocalServer : IDisposable
        {
            private readonly HttpListener listener;
            private readonly CancellationTokenSource cts;

            public LocalServer(string url, Action<HttpListenerContext> onRequest = null)
            {
                this.listener = new HttpListener();
                this.listener.Prefixes.Add(url);
                this.listener.Start();
                this.cts = new CancellationTokenSource();

                Task.Run(
                    () =>
                    {
                        if (!this.cts.IsCancellationRequested)
                        {
                            HttpListenerContext context = this.listener.GetContext();
                            if (onRequest != null)
                            {
                                onRequest(context);
                            }
                            else
                            {
                                context.Response.StatusCode = 200;
                            }

                            context.Response.OutputStream.Close();
                            context.Response.Close();
                        }
                    },
                    this.cts.Token);
            }

            public void Dispose()
            {
                this.cts.Cancel(false);
                this.listener.Abort();
                ((IDisposable)this.listener).Dispose();
                this.cts.Dispose();
            }
        }

    }
}
