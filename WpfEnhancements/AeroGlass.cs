using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace WpfEnhancements
{
	[StructLayout(LayoutKind.Sequential)]
	public struct MARGINS
	{
		public MARGINS(int left, int right, int top, int bottom)
		{
			Left = left;
			Right = right;
			Top = top;
			Bottom = bottom;
		}

		public int Left;
		public int Right;
		public int Top;
		public int Bottom;
	} 

	public static class AeroGlass
	{
		public const int WM_DWMCOMPOSITIONCHANGED = 0x031E;

		[DllImport("dwmapi.dll", PreserveSig = false)]
		static extern void DwmExtendFrameIntoClientArea(IntPtr hWnd, ref MARGINS pMarInset);

		[DllImport("dwmapi.dll", PreserveSig = false)]
		static extern bool DwmIsCompositionEnabled();

		public static bool ExtendGlassFrame(Window window, Thickness margin)
		{
			if (Environment.OSVersion.Version.Major < 6)
				return false;

			IntPtr hwnd = new WindowInteropHelper(window).Handle;

			MARGINS margins = new MARGINS((int)margin.Left, (int)margin.Right, (int)margin.Top, (int)margin.Bottom);

			// The background must be transparent in order to use glass
			// WPF
			window.Background = Brushes.Transparent;

			return ExtendGlassFrame(hwnd, margins);
		}

		public static bool ExtendGlassFrame(IntPtr hwnd, MARGINS margins)
		{
			// Can we draw glass?
			if (!DwmIsCompositionEnabled())
				return false;			

			if (hwnd == IntPtr.Zero)
				throw new InvalidOperationException("Window must be shown before drawing glass");

			// The background must be transparent in order to use glass
			// Win32
			HwndSource.FromHwnd(hwnd).CompositionTarget.BackgroundColor = Colors.Transparent;

			DwmExtendFrameIntoClientArea(hwnd, ref margins);

			return true;
		}
	}
}
