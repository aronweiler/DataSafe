using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel;

namespace DataSafeLibrary
{
	[ServiceBehavior(ConcurrencyMode = ConcurrencyMode.Single, InstanceContextMode = InstanceContextMode.Single)]
	public class DataSafeInterface : IDataSafeInterface
	{
		public bool IsServiceAcceptingRequests()
		{
			return true;
		}

		public void AddFileToProcess(string fileName)
		{
			// Presumably this file is encrypted, check that, then add it to the queue
			string[] encryptedFile = Encryption.Instance.GetFilesOfType(new string[] { fileName }, true);

			// Get the password
			if (encryptedFile.Length >= 1)
			{
				string pwd = Encryption.Instance.GetPasswordFromUi();

				if (!string.IsNullOrEmpty(pwd))
				{
					PasswordAndFiles pwdfiles = new PasswordAndFiles(pwd, encryptedFile.ToArray(), false);

					Encryption.Instance.AddFiles(pwdfiles);
				}
			}
		}
	}
}
