using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows;

namespace DataSafeWpf
{
	[Flags]
	public enum TaskDialogButtons
	{
		OK = 0x0001,
		Cancel = 0x0008,
		Yes = 0x0002,
		No = 0x0004,
		Retry = 0x0010,
		Close = 0x0020
	}

	public enum TaskDialogIcon
	{
		Information = UInt16.MaxValue - 2,
		Warning = UInt16.MaxValue,
		Stop = UInt16.MaxValue - 1,
		Question = 0,
		SecurityWarning = UInt16.MaxValue - 5,
		SecurityError = UInt16.MaxValue - 6,
		SecuritySuccess = UInt16.MaxValue - 7,
		SecurityShield = UInt16.MaxValue - 3,
		SecurityShieldBlue = UInt16.MaxValue - 4,
		SecurityShieldGray = UInt16.MaxValue - 8
	}

	public enum TaskDialogResult
	{
		OK=1,
		Cancel=2,
		Retry=4,
		Yes=6,
		No=7,
		Close=8
	}

	public static class TaskDialogWindow
	{
		[DllImport("comctl32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
		static extern TaskDialogResult TaskDialog(IntPtr hWndParent, IntPtr hInstance, String title, String mainInstruction, String content, TaskDialogButtons buttons, TaskDialogIcon icon);

		public static TaskDialogResult Show(Window owner, string text)
		{
			return Show(owner, text, null, null, TaskDialogButtons.OK);
		}

		public static TaskDialogResult Show(Window owner, string text, string instruction)
		{
			return Show(owner, text, instruction, null, TaskDialogButtons.OK, 0);
		}

		public static TaskDialogResult Show(Window owner, string text, string instruction, string caption)
		{
			return Show(owner, text, instruction, caption, TaskDialogButtons.OK, 0);
		}

		public static TaskDialogResult Show(Window owner, string text, string instruction, string caption, TaskDialogButtons buttons)
		{
			return Show(owner, text, instruction, caption, buttons, 0);
		}

		public static TaskDialogResult Show(Window owner, string text, string instruction, string caption, TaskDialogButtons buttons, TaskDialogIcon icon)
		{
			return ShowInternal(owner, text, instruction, caption, buttons, icon);
		}

		public static TaskDialogResult Show(string text)
		{
			return Show(text, null, null, TaskDialogButtons.OK);
		}

		public static TaskDialogResult Show(string text, string instruction)
		{
			return Show(text, instruction, null, TaskDialogButtons.OK, 0);
		}

		public static TaskDialogResult Show(string text, string instruction, string caption)
		{
			return Show(text, instruction, caption, TaskDialogButtons.OK, 0);
		}

		public static TaskDialogResult Show(string text, string instruction, string caption, TaskDialogButtons buttons)
		{
			return Show(text, instruction, caption, buttons, 0);
		}

		public static TaskDialogResult Show(string text, string instruction, string caption, TaskDialogButtons buttons, TaskDialogIcon icon)
		{
			return ShowInternal(null, text, instruction, caption, buttons, icon);
		}

		static TaskDialogResult ShowInternal(Window window, string text, string instruction, string caption, TaskDialogButtons buttons, TaskDialogIcon icon)
		{
			IntPtr windowHandle = IntPtr.Zero;

			if (window != null)
			{
				WindowInteropHelper win = new WindowInteropHelper(window);
				windowHandle = win.Handle;
			}

			return TaskDialog(windowHandle, IntPtr.Zero, caption, instruction, text, buttons, icon);
		}
	}
}
