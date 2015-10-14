using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthorizeRole
{
    public interface IAuthorizer
    {
        bool VerifyToken(string token, ClientEntity client);
        string BearerToken(ClientEntity client);
    }
}
