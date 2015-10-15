using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using Microsoft.WindowsAzure.ServiceRuntime;
using System;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Web.Http;
using System.Collections.Generic;
using System.Linq;

namespace AuthorizeRole
{
    public class AuthorizeController : ApiController
    {
        CloudTableClient tableClient;
        IAuthorizer authAlgo;

        public AuthorizeController()
        {
            authAlgo = new Authorizer();
        }
        
        public HttpResponseMessage Get()
        {
            return new HttpResponseMessage()
            {
                Content = new StringContent("Hello from OWIN!")
            };
        }

        public HttpResponseMessage Get(int id)
        {
            string msg = String.Format("Hello from OWIN (id = {0})", id);
            return new HttpResponseMessage()
            {
                Content = new StringContent(msg)
            };
        }

        [Route("verify")]
        public IHttpActionResult Post([FromBody] Credentials credentials)
        {
            IHttpActionResult result;

            var jwt = new JwtSecurityToken(credentials.token);
            var scope = jwt.Claims.FirstOrDefault(c => c.Type == "scope");
            var iss = jwt.Claims.FirstOrDefault(c => c.Type == "iss");

            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(RoleEnvironment.GetConfigurationSettingValue("StorageConnectionString"));
            CloudTableClient tableClient = storageAccount.CreateCloudTableClient();
            // Create the table if it doesn't exist.
            CloudTable table = tableClient.GetTableReference("Clients");
            table.CreateIfNotExists();

            // Create a retrieve operation that takes a customer entity.
            TableOperation retrieveOperation = TableOperation.Retrieve<ClientEntity>(scope.Value, iss.Value);
            // Execute the retrieve operation.
            TableResult retrievedResult = table.Execute(retrieveOperation);

            //Print the phone number of the result.
            if (retrievedResult.Result != null)
            {
                var client = (ClientEntity)retrievedResult.Result;
                var verified = authAlgo.VerifyToken(credentials.token, client);
                if (verified)
                {
                    Credentials creds = new Credentials()
                    {
                        token = authAlgo.BearerToken(client)
                    };

                    result = Ok<Credentials>(creds);
                }
                else
                {
                    result = Unauthorized();
                }
            }
            else
            {
                result = BadRequest();
            }

            return result;
        }
    }
}
