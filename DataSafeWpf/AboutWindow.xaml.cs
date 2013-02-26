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
using System.Diagnostics;

namespace DataSafeWpf
{
	/// <summary>
	/// Interaction logic for AboutWindow.xaml
	/// </summary>
	public partial class AboutWindow : Window
	{
		public AboutWindow()
		{
			InitializeComponent();
		}

		private void Button_Click(object sender, RoutedEventArgs e)
		{
			this.Close();
		}

		protected override void OnSourceInitialized(EventArgs e)
		{
			base.OnSourceInitialized(e);

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

		private void Hyperlink_Click(object sender, RoutedEventArgs e)
		{
			Process.Start("mailto:aronweiler@gmail.com");
		}
	}
}
