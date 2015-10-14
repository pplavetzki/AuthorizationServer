using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.WindowsAzure;
using Microsoft.WindowsAzure.Diagnostics;
using Microsoft.WindowsAzure.ServiceRuntime;
using Microsoft.WindowsAzure.Storage;
using Microsoft.Owin.Hosting;

namespace AuthorizeRole
{
    public class WorkerRole : RoleEntryPoint
    {
        private readonly CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
        private readonly ManualResetEvent runCompleteEvent = new ManualResetEvent(false);

        private IDisposable _app = null;

        public override void Run()
        {
            Trace.TraceInformation("AuthorizeRole is running");

            try
            {
                this.RunAsync(this.cancellationTokenSource.Token).Wait();
            }
            finally
            {
                this.runCompleteEvent.Set();
            }
        }

        public override bool OnStart()
        {
            // Set the maximum number of concurrent connections
            ServicePointManager.DefaultConnectionLimit = 12;

            // For information on handling configuration changes
            // see the MSDN topic at http://go.microsoft.com/fwlink/?LinkId=166357.

            ServicePointManager.DefaultConnectionLimit = 12;

            // New code:
            var endpoint = RoleEnvironment.CurrentRoleInstance.InstanceEndpoints["AuthorizeEndPoint"];
            string baseUri = String.Format("{0}://{1}",
                endpoint.Protocol, "localhost:10100");

            Trace.TraceInformation(String.Format("Starting AuthorizeRole OWIN at {0}", baseUri),
                "Information");

            _app = WebApp.Start<Startup>(new StartOptions(url: baseUri));

            return base.OnStart();

        }

        public override void OnStop()
        {
            Trace.TraceInformation("AuthorizeRole is stopping");

            if (_app != null)
            {
                _app.Dispose();
            }
            base.OnStop();

            Trace.TraceInformation("AuthorizeRole has stopped");
        }

        private async Task RunAsync(CancellationToken cancellationToken)
        {
            // TODO: Replace the following with your own logic.
            while (!cancellationToken.IsCancellationRequested)
            {
                Trace.TraceInformation("Working");
                await Task.Delay(1000);
            }
        }
    }
}
