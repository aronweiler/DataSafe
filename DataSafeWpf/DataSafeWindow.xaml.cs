using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using DataSafeLibrary;
using System.Configuration;
using System.Windows.Media.Animation;
using System.ComponentModel;
using System.Windows.Resources;
using System.IO;
using WpfEnhancements;
using System.Windows.Interop;
using System.Windows.Threading;
using System.Threading;
using System.Reflection;

namespace DataSafeWpf
{
	/// <summary>
	/// Interaction logic for Window1.xaml
	/// </summary>
	public partial class DataSafeWindow : Window
	{
		bool closing = false;
		bool showingFiles = false;
		System.Windows.Forms.NotifyIcon niDataSafe;
		System.Windows.Forms.ContextMenuStrip ctxDataSafeMenu;

		Settings settings = new Settings();

		public DataSafeWindow()
		{
			InitializeComponent();

			DataSafeRegistrySettings.AssociateFiles(".enc", Assembly.GetExecutingAssembly().Location);

			CreateContextMenu();
			CreateNotifyIcon();

			Encryption.Instance.BlockFinished += fileEncryption_BlockFinished;
			Encryption.Instance.FileFinished += fileEncryption_FileFinished;
			Encryption.Instance.FileStarted += fileEncryption_FileStarted;
			Encryption.Instance.FilesAddedToEncrypt += fileEncryption_FilesAddedToEncrypt;
			Encryption.Instance.FilesAddedToDecrypt += fileEncryption_FilesAddedToDecrypt;
			Encryption.Instance.AllWorkFinished += fileEncryption_AllWorkFinished;
			Encryption.Instance.WipingSourceFileBlockFinished += fileEncryption_WipingSourceFileBlockFinished;
			Encryption.Instance.GetPassword += fileEncryption_GetPassword;

			this.Topmost = settings.AlwaysOnTop;

			if (settings.StartHidden)
				this.Hide();

			Encryption.Instance.AppStarted();
		}

		System.Drawing.Icon FromImageSource(ImageSource icon)
		{
			if (icon == null)
			{
				return null;
			}

			Uri iconUri = new Uri(icon.ToString());

			return new System.Drawing.Icon(Application.GetResourceStream(iconUri).Stream);
		}

		void CreateContextMenu()
		{
			Stream open = Application.GetResourceStream(new Uri("pack://application:,,,/DataSafeWpf;component/Resources/open.gif")).Stream;
			Stream exit = Application.GetResourceStream(new Uri("pack://application:,,,/DataSafeWpf;component/Resources/exit.gif")).Stream;

			ctxDataSafeMenu = new System.Windows.Forms.ContextMenuStrip();

			ctxDataSafeMenu.Items.Add("&Open", System.Drawing.Image.FromStream(open), openToolStripMenuItem_Click);
			ctxDataSafeMenu.Items.Add("&About", null, aboutToolStripMenuItem_Click);
			ctxDataSafeMenu.Items.Add("-");
			ctxDataSafeMenu.Items.Add("&Exit", System.Drawing.Image.FromStream(exit), exitToolStripMenuItem_Click);
		}

		void CreateNotifyIcon()
		{
			niDataSafe = new System.Windows.Forms.NotifyIcon();

			niDataSafe.BalloonTipIcon = System.Windows.Forms.ToolTipIcon.Info;
			niDataSafe.BalloonTipText = "DataSafe 2008 with AES";
			niDataSafe.ContextMenuStrip = ctxDataSafeMenu;

			niDataSafe.Icon = FromImageSource(Icon);
			niDataSafe.Text = "DataSafe AES";
			niDataSafe.Visible = true;
			niDataSafe.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(niDataSafe_MouseDoubleClick);
		}

		private void openToolStripMenuItem_Click(object sender, EventArgs e)
		{
			this.Show();
			this.BringIntoView();
		}
		
		private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
		{
			this.Show();
			this.BringIntoView();

			AboutWindow about = new AboutWindow();
			about.Owner = this;
			about.WindowStartupLocation = WindowStartupLocation.CenterOwner;
			about.ShowDialog();
		}

		private void exitToolStripMenuItem_Click(object sender, EventArgs e)
		{
			closing = true;
			this.Close();
		}

		protected override void OnClosing(CancelEventArgs e)
		{
			e.Cancel = !closing;

			if (closing)
			{
				niDataSafe.Dispose();
				base.OnClosing(e);
			}
			else
			{
				// WPF retardation
				Dispatcher.BeginInvoke(DispatcherPriority.Normal, (ThreadStart)delegate() { Hide(); });
			}
		}

		private void niDataSafe_MouseDoubleClick(object sender, System.Windows.Forms.MouseEventArgs e)
		{
			this.Show();
		}

		private void lblEncrypt_DragOver(object sender, DragEventArgs e)
		{
			if (e.Data.GetDataPresent(DataFormats.FileDrop))
			{
				string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];

				if (files.Length > 0)
				{
					e.Effects = DragDropEffects.All;
					e.Handled = true;
					return;
				}

				//if (files.Length > 20 || Encryption.Instance.GetDecryptedFilesOnly(files).Length > 0)
				//{
				//    e.Effects = DragDropEffects.All;
				//    e.Handled = true;
				//    return;
				//}
			}

			e.Effects = DragDropEffects.None;
			e.Handled = true;
		}

		private void lblDecrypt_DragOver(object sender, DragEventArgs e)
		{
			e.Effects = DragDropEffects.None;

			if (e.Data.GetDataPresent(DataFormats.FileDrop))
			{
				string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];

				if (files.Length > 0)
				{
					e.Effects = DragDropEffects.All;
					e.Handled = true;
					return;
				}

				//if (files.Length > 20 || Encryption.Instance.GetEncryptedFilesOnly(files).Length > 0)
				//{
				//    e.Effects = DragDropEffects.All;
				//    e.Handled = true;
				//    return;
				//}
			}

			e.Effects = DragDropEffects.None;
			e.Handled = true;
		}		

		private void lblEncrypt_Drop(object sender, DragEventArgs e)
		{
			this.Cursor = Cursors.Wait;

			string[] files = Encryption.Instance.GetFilesOfType(e.Data.GetData(DataFormats.FileDrop) as string[], false);

			this.Cursor = Cursors.Arrow;

            if (files.Length > 0)
            {
                this.Activate();

                PasswordWindow password = new PasswordWindow(true);
				password.Owner = this;
				password.WindowStartupLocation = WindowStartupLocation.CenterOwner;				

                if (password.ShowDialog() == true)
                {
                    Encryption.Instance.AddFiles(new PasswordAndFiles(password.Password, files, true));
                }
            }
		}

		internal void lblDecrypt_Drop(object sender, DragEventArgs e)
		{
			this.Cursor = Cursors.Wait;

			string[] files = Encryption.Instance.GetFilesOfType(e.Data.GetData(DataFormats.FileDrop) as string[], true);

			this.Cursor = Cursors.Arrow;

            if (files.Length > 0)
            {
                this.Activate();

                PasswordWindow password = new PasswordWindow(false);
				password.Owner = this;
				password.WindowStartupLocation = WindowStartupLocation.CenterOwner;

                if (password.ShowDialog() == true)
                {
                    Encryption.Instance.AddFiles(new PasswordAndFiles(password.Password, files, false));
                }
            }
		}

		void fileEncryption_FileFinished(string file, int total, int completed)
		{
			this.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Normal, (Action)delegate
			{
				progFiles.Maximum = total;
				progFiles.Value = completed;
				lblFilesCompleted.Content = string.Format("{0} of {1}", completed, total);

				if (file != null)
				{
					var item = from i in lstFiles.Items.Cast<Label>() where i.Content.ToString() == file select i;

					lstFiles.Items.Remove(item.First());
				}
				else
				{
					lblCurrentDirectory.Content = string.Empty;
					lblCurrentFile.Content = string.Empty;					
				}
			});
		}

		void fileEncryption_BlockFinished(long total, long completed)
		{
			this.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Normal, (Action)delegate
			{
				progBlocks.Maximum = (int)total;
				progBlocks.Value = (int)completed;
				lblBytesCompleted.Content = string.Format("{0} of {1}", completed, total);
				lblBytesLabel.Content = "Bytes Completed";
			});
		}

		void fileEncryption_WipingSourceFileBlockFinished(int currentPass, int totalPasses, long total, long completed)
		{
			this.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Normal, (Action)delegate
			{
				progBlocks.Maximum = (int)total;
				progBlocks.Value = (int)completed;
				lblBytesCompleted.Content = string.Format("Wiping Source File... Pass {0} of {1}", currentPass, totalPasses);
				lblBytesLabel.Content = string.Empty;
			});
		}

		void fileEncryption_FileStarted(string fileName)
		{
			this.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Normal, (Action)delegate
			{
				lblCurrentDirectory.Content = System.IO.Path.GetDirectoryName(fileName);
				lblCurrentFile.Content = System.IO.Path.GetFileName(fileName);

				ShowFiles();
			});
		}

		void fileEncryption_FilesAddedToDecrypt(string[] files)
		{
			this.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Normal, (Action)delegate
			{
				foreach (string file in files)
				{
					Label l = new Label();
					l.Content = file;
					l.Foreground = Brushes.Green;
					l.FontWeight = FontWeights.Bold;
					lstFiles.Items.Add(l);
				}
			});
		}

		void fileEncryption_FilesAddedToEncrypt(string[] files)
		{
			this.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Normal, (Action)delegate
			{
				foreach (string file in files)
				{
					Label l = new Label();
					l.Content = file;
					l.Foreground = Brushes.Red;
					l.FontWeight = FontWeights.Bold;
					lstFiles.Items.Add(l);
				}
			});
		}

		void fileEncryption_AllWorkFinished()
		{
			this.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Normal, (Action) delegate
			{
				progFiles.Maximum = 100;
				progFiles.Value = 0;
				lblFilesCompleted.Content = string.Format("{0} of {1}", 0, 0);

				progBlocks.Maximum = 100;
				progBlocks.Value = 0;
				lblBytesCompleted.Content = string.Format("{0} of {1}", 0, 0);

				lblBytesLabel.Content = "Bytes Completed";

				lstFiles.Items.Clear();
				lstFiles.Items.Clear();
				lblCurrentDirectory.Content = string.Empty;
				lblCurrentFile.Content = string.Empty;

				HideFiles();
			});
		}

		public string fileEncryption_GetPassword()
		{
			this.Show();
			this.Activate();

			PasswordWindow password = new PasswordWindow(false);
			password.Owner = this;
			password.WindowStartupLocation = WindowStartupLocation.CenterOwner;

			if (password.ShowDialog() == true)
				return password.Password;
			else
				return null;
			
		}

		void ShowFiles()
		{
			if (!showingFiles)
			{
				DoubleAnimation anim = new DoubleAnimation(0, 100, new Duration(TimeSpan.FromSeconds(.5)));

				grdFiles.BeginAnimation(Grid.HeightProperty, anim);

				showingFiles = true;
			}
		}

		void HideFiles()
		{
			if (showingFiles)
			{
				DoubleAnimation anim = new DoubleAnimation(grdFiles.Height, 0, new Duration(TimeSpan.FromSeconds(.5)));

				grdFiles.BeginAnimation(Grid.HeightProperty, anim);

				showingFiles = false;				
			}
		}

		protected override void OnSourceInitialized(EventArgs e)
		{
			base.OnSourceInitialized(e);

			if (Environment.OSVersion.Version.Major < 6)
			{
				this.Background = Brushes.LightSteelBlue;			
				return;
			}

			// Extend glass
			AeroGlass.ExtendGlassFrame(this, new Thickness(-1));//(2, 5, 2, 20));

			// Next attach a window handler to inform us if composition is turned on at a later point.
			IntPtr hwnd = new WindowInteropHelper(this).Handle;
			HwndSource.FromHwnd(hwnd).AddHook(new HwndSourceHook(WndProc));
		}		

		IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
		{
			if (msg == AeroGlass.WM_DWMCOMPOSITIONCHANGED)
			{
				AeroGlass.ExtendGlassFrame(this, new Thickness(-1));
				handled = true;
			}

			return IntPtr.Zero;
		}
	}
}
