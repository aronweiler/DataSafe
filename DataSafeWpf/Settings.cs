using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace DataSafeWpf
{
	public class Settings
	{
		const string DataSafeEncryptedFile = "DataSafeEncryptedFile";

		public static void AssociateFiles(string fileExtension, string exeLocation)
		{
			// Clear out the old one
			Registry.ClassesRoot.DeleteSubKey(fileExtension, false);

			RegistryKey extKey = Registry.ClassesRoot.CreateSubKey(fileExtension);

			// does null work here?  Need to set the (Default) value to the following			
            extKey.SetValue(null, DataSafeEncryptedFile, RegistryValueKind.String);
			extKey.SetValue("DefaultIcon", string.Format("\"{0}\", 0", exeLocation));
			
			RegistryKey shellKey = Registry.ClassesRoot.CreateSubKey(DataSafeEncryptedFile);

			shellKey.SetValue(null, "DataSafe Encrypted File", RegistryValueKind.String);

			RegistryKey commandKey = shellKey.CreateSubKey("shell").CreateSubKey("Open").CreateSubKey("Command");

			commandKey.SetValue(null, string.Format("\"{0}\" \"%1 %*\"", exeLocation), RegistryValueKind.String);

			// C:\Users\Aron\AppData\Roaming\Microsoft\Windows\SendTo
			
		}
	}
}
