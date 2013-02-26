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
using System.Windows.Shapes;
using System.Windows.Interop;
using WpfEnhancements;

namespace DataSafeWpf
{
    /// <summary>
    /// Interaction logic for PasswordWindow.xaml
    /// </summary>
    public partial class PasswordWindow : Window
    {
		bool showConfirm = true;

        public PasswordWindow(bool showConfirmPassword)
        {
            InitializeComponent();

			showConfirm = showConfirmPassword;

			if (!showConfirm)
			{
				grdMain.RowDefinitions[1].Height = new GridLength(0);
				this.Title = "Decryption Password";
			}
			else
			{
				this.Title = "Encryption Password";
			}

			txtPassword.Focus();
        }

        public string Password 
        {
            get
            {
                return txtPassword.Password;
            }
        }

        private void cmdOk_Click(object sender, RoutedEventArgs e)
        {
			if (txtConfirm.Password == txtPassword.Password || !showConfirm)
			{
				DialogResult = true;
				Close();
			}
			else
			{
				MessageBox.Show(this, "Passwords do not match, please retype your password", "DataSafe - Invalid Password", MessageBoxButton.OK, MessageBoxImage.Stop);
				txtPassword.Clear();
				txtConfirm.Clear();

				txtPassword.Focus();
			}
        }

        private void cmdCancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

		protected override void OnSourceInitialized(EventArgs e)
		{
			base.OnSourceInitialized(e);

			// Extend glass
			AeroGlass.ExtendGlassFrame(this, new Thickness(-1));

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
