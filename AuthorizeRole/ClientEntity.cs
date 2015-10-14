using Microsoft.WindowsAzure.Storage.Table;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthorizeRole
{
    public class ClientEntity : TableEntity
    {
        public ClientEntity(string scope, string iss)
        {
            this.PartitionKey = scope;
            this.RowKey = iss;
        }

        public ClientEntity() { }

        public DateTime IssuedDate { get; set; }
        public string ResponsibleEmail { get; set; }
        public string Issuer { get; set; }
        public string SecurityKey { get; set; }
        public string Audience { get; set; }
    }
}
