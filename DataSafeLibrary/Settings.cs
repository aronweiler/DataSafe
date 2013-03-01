using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Linq;
using System.Text;

namespace DataSafeLibrary
{
	public class Settings : ApplicationSettingsBase, INotifyPropertyChanged
	{
		public event PropertyChangedEventHandler PropertyChanged;

		[UserScopedSettingAttribute()]
		[DefaultSettingValueAttribute("false")]
		public bool AlwaysOnTop
		{
			get { return (bool)this["AlwaysOnTop"]; }
			set
			{
				this["AlwaysOnTop"] = value;
				Notify("AlwaysOnTop");
			}
		}

		[UserScopedSettingAttribute()]
		[DefaultSettingValueAttribute("false")]
		public bool StartHidden
		{
			get { return (bool)this["StartHidden"]; }
			set
			{
				this["StartHidden"] = value;
				Notify("StartHidden");
			}
		}

		[UserScopedSettingAttribute()]
		[DefaultSettingValueAttribute("false")]
		public bool BufferDetermined
		{
			get { return (bool)this["BufferDetermined"]; }
			set
			{
				this["BufferDetermined"] = value;
				Notify("BufferDetermined");
			}
		}

		[UserScopedSettingAttribute()]
		[DefaultSettingValueAttribute("10240")]
		public int ReadBufferSizeInBytes
		{
			get { return (int)this["ReadBufferSizeInBytes"]; }
			set
			{
				this["ReadBufferSizeInBytes"] = value;
				Notify("ReadBufferSizeInBytes");
			}
		}

		[UserScopedSettingAttribute()]
		[DefaultSettingValueAttribute("10240")]
		public int WriteBufferSizeInBytes
		{
			get { return (int)this["WriteBufferSizeInBytes"]; }
			set
			{
				this["WriteBufferSizeInBytes"] = value;
				Notify("WriteBufferSizeInBytes");
			}
		}

		[UserScopedSettingAttribute()]
		[DefaultSettingValueAttribute("DataSafe")]
		public string EncryptedFilePrefix
		{
			get { return this["EncryptedFilePrefix"] as string; }
			set
			{
				this["EncryptedFilePrefix"] = value;
				Notify("EncryptedFilePrefix");
			}
		}		

		[UserScopedSettingAttribute()]
		[DefaultSettingValueAttribute("true")]
		public bool MakeSourceUnrecoverable
		{
			get { return (bool)this["MakeSourceUnrecoverable"]; }
			set
			{
				this["MakeSourceUnrecoverable"] = value;
				Notify("MakeSourceUnrecoverable");
			}
		}

		[UserScopedSettingAttribute()]
		[DefaultSettingValueAttribute("2")]
		public int WipeSourceFilesPasses
		{
			get { return (int)this["WipeSourceFilesPasses"]; }
			set
			{
				this["WipeSourceFilesPasses"] = value;
				Notify("WipeSourceFilesPasses");
			}
		}

		private void Notify(string name)
		{
			if (PropertyChanged != null)
				PropertyChanged(this, new PropertyChangedEventArgs(name));

			Save();
		}
	}
}
