using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Windows;
using DataSafeLibrary;
using System.Diagnostics;
using System.Windows.Interop;
using System.Windows.Threading;
using System.ServiceModel;

namespace DataSafeWpf
{
	/// <summary>
	/// Interaction logic for App.xaml
	/// </summary>
	public partial class App : Application
	{
		string[] args;

		protected override void OnStartup(StartupEventArgs e)
		{
			if (e.Args.Length > 0)
			{
				args = e.Args;

				// Call the already active instance if there is one, otherwise call the new instance? hmm
				if (Process.GetProcessesByName(Process.GetCurrentProcess().ProcessName).Length > 1)
				{
					// There is already a DataSafe app running... call into it and pass the arguments then close this instance
					try
					{
						ChannelFactory<IDataSafeInterface> dataSafeClientFactory = new ChannelFactory<IDataSafeInterface>("DataSafeInterfaceClient");
						IDataSafeInterface dataSafeInterface = dataSafeClientFactory.CreateChannel();

						if (dataSafeInterface.IsServiceAcceptingRequests())
							dataSafeInterface.AddFileToProcess(args[0]);
						else
							throw new Exception();
					}
					catch (Exception ex)
					{
						Console.WriteLine(ex.ToString());
						MessageBox.Show("DataSafeInterface Service is not accepting requests, please end all other DataSafe sessions and retry");
					}

					Application.Current.Shutdown(0);
				}
				else 
				{
					// Start the application and pass it the arguments
					base.OnStartup(e);

					Encryption.Instance.ApplicationStarted += new OnAppStarted(Instance_ApplicationStarted);
				}				
			}
			else
			{
				// Just start the application
				base.OnStartup(e);
			}
		}

		void Instance_ApplicationStarted()
		{
			Encryption.DataSafeInterface.AddFileToProcess(args[0]);
		}
	}
}
