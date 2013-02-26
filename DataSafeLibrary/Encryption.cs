using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Threading;
using System.Configuration;
using System.ServiceModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DataSafeLibrary
{
	public delegate void OnBlockFinished(long total, long completed);
	public delegate void OnWipingSourceFileBlockFinished(int currentPass, int totalPasses, long total, long completed);
	public delegate void OnFileFinished(string file, int total, int completed);
	public delegate void OnFileStarted(string fileName);
	public delegate void OnFilesAdded(string[] files);
	public delegate void OnAllWorkFinished();
	public delegate string OnGetPassword();
	public delegate void OnAppStarted();

	public class Encryption
	{
		public event OnBlockFinished BlockFinished;
		public event OnWipingSourceFileBlockFinished WipingSourceFileBlockFinished;
		public event OnFileFinished FileFinished;
		public event OnFileStarted FileStarted;
		public event OnFilesAdded FilesAddedToEncrypt;
		public event OnFilesAdded FilesAddedToDecrypt;
		public event OnAllWorkFinished AllWorkFinished;
		public event OnGetPassword GetPassword;
		public event OnAppStarted ApplicationStarted;

		static readonly int passwordIterations = 1000;
		static readonly int passwordSaltSize = 8;
		static readonly int passwordSize = 16;

		string DataSafeFileNamePrefix = "DataSafe";
		static readonly string DataSafeFileExtension = ".enc";
		readonly bool HideFileNames = true;
		readonly bool WipeSourceFiles = false;
		readonly int WipeSourceFilesPasses = 1;

		byte[] readBuffer;
		byte[] zeroBuffer;
		byte[] oneBuffer;

		const uint FILE_FLAG_NO_BUFFERING = 0x20000000;

		[DllImport("kernel32", SetLastError = true)]
		static extern unsafe SafeFileHandle CreateFile(
			string FileName,           // file name
			uint DesiredAccess,        // access mode
			uint ShareMode,            // share mode
			IntPtr SecurityAttributes, // Security Attr
			uint CreationDisposition,  // how to create
			uint FlagsAndAttributes,   // file attributes
			IntPtr hTemplate // template file  
			);

		// For large files this is the best performing buffer size
		static byte[] buffer = new byte[32768];

		Queue<PasswordAndFiles> filesToProcess = new Queue<PasswordAndFiles>();

		int counter = 0;
		int totalFiles;
		Thread processThread;
		ManualResetEvent mreFilesReady = new ManualResetEvent(false);

		static Encryption instance;
		static IDataSafeInterface dataSafeInterface = new DataSafeInterface();

		ServiceHost host;

		public static IDataSafeInterface DataSafeInterface
		{
			get { return Encryption.dataSafeInterface; }
			set { Encryption.dataSafeInterface = value; }
		}

		public static Encryption Instance
		{
			get
			{
				if (instance == null)
					instance = new Encryption();

				return instance;
			}
		}

		Encryption()
		{
			int bufferSize = 10240;
			ThreadPriority threadPriority = ThreadPriority.Normal;

			if (ConfigurationManager.AppSettings["BufferSizeInBytes"] != null)
				bufferSize = Convert.ToInt32(ConfigurationManager.AppSettings["BufferSizeInBytes"]);

			if (ConfigurationManager.AppSettings["EncryptedFilePrefix"] != null)
				DataSafeFileNamePrefix = ConfigurationManager.AppSettings["EncryptedFilePrefix"];

			if (ConfigurationManager.AppSettings["EncryptionThreadPriority"] != null)
				threadPriority = (ThreadPriority)Enum.Parse(typeof(ThreadPriority), ConfigurationManager.AppSettings["EncryptionThreadPriority"]);

			if (ConfigurationManager.AppSettings["HideFileNames"] != null)
				HideFileNames = Convert.ToBoolean(ConfigurationManager.AppSettings["HideFileNames"]);

			if (ConfigurationManager.AppSettings["WipeSourceFiles"] != null)
				WipeSourceFiles = Convert.ToBoolean(ConfigurationManager.AppSettings["WipeSourceFiles"]);

			if (ConfigurationManager.AppSettings["WipeSourceFilesPasses"] != null)
				WipeSourceFilesPasses = Convert.ToInt32(ConfigurationManager.AppSettings["WipeSourceFilesPasses"]);

			readBuffer = new byte[bufferSize];
			zeroBuffer = new byte[bufferSize];
			oneBuffer = new byte[bufferSize];
			FillOneBuffer();

			processThread = new Thread(ProcessFiles);
			processThread.IsBackground = true;
			processThread.Priority = threadPriority;
			processThread.Start();

			StartDataSafeInterfaceService();
		}

		public void AppStarted()
		{
			if (ApplicationStarted != null)
				ApplicationStarted();
		}

		void StartDataSafeInterfaceService()
		{
			host = new ServiceHost(dataSafeInterface);

			host.Open();
		}

		void FillOneBuffer()
		{
			for (int i = 0; i < oneBuffer.Length; i++)
				oneBuffer[i] = 1;
		}

		public string[] GetEncryptedFilesOnly(string[] files)
		{
			files = ReplaceDirectoriesWithFiles(files);

			List<string> encryptedFiles = new List<string>();

			foreach (string file in files)
			{
				try
				{
					using (FileStream inputFile = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
					{
						// Get the header information
						byte[] headerBytes = new byte[EncryptionTypes.AesEncryptionId.Length];
						inputFile.Read(headerBytes, 0, headerBytes.Length);

						inputFile.Position = 0;

						EncryptionHeader header = new EncryptionHeader(headerBytes);

						if (header.HeaderEncryptionType != EncryptionHeaderType.Unknown)
							encryptedFiles.Add(file);
					}
				}
				catch
				{
				}
			}

			return encryptedFiles.ToArray();
		}

		public string[] GetDecryptedFilesOnly(string[] files)
		{
			files = ReplaceDirectoriesWithFiles(files);

			List<string> decryptedFiles = new List<string>();

			foreach (string file in files)
			{
				try
				{
					using (FileStream inputFile = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
					{
						// Get the header information
						byte[] headerBytes = new byte[EncryptionTypes.AesEncryptionId.Length];
						inputFile.Read(headerBytes, 0, headerBytes.Length);

						inputFile.Position = 0;

						EncryptionHeader header = new EncryptionHeader(headerBytes);

						if (header.HeaderEncryptionType == EncryptionHeaderType.Unknown)
							decryptedFiles.Add(file);
					}
				}
				catch
				{
				}
			}

			return decryptedFiles.ToArray();
		}

		public void AddFiles(PasswordAndFiles passwordAndFiles)
		{
			ReplaceDirectoriesWithFiles(passwordAndFiles);

			if (!filesToProcess.Contains(passwordAndFiles))
			{
				filesToProcess.Enqueue(passwordAndFiles);
				totalFiles += passwordAndFiles.Files.Length;

				if (passwordAndFiles.Encrypt)
				{
					if (FilesAddedToEncrypt != null)
						FilesAddedToEncrypt(passwordAndFiles.Files);
				}
				else
				{
					if (FilesAddedToDecrypt != null)
						FilesAddedToDecrypt(passwordAndFiles.Files);
				}

				if (FileFinished != null)
					FileFinished(null, totalFiles, counter);

				mreFilesReady.Set();
			}
		}

		void ReplaceDirectoriesWithFiles(PasswordAndFiles passwordAndFiles)
		{
			passwordAndFiles.Files = ReplaceDirectoriesWithFiles(passwordAndFiles.Files);
		}

		string[] ReplaceDirectoriesWithFiles(string[] oldFiles)
		{
			List<string> files = new List<string>();

			foreach (string file in oldFiles)
			{
				if (Directory.Exists(file))
				{
					files.AddRange(GetAllFilesInDirectories(new string[] { file }));
				}
				else
				{
					files.Add(file);
				}
			}

			return files.ToArray();
		}

		List<string> GetAllFilesInDirectories(string[] directories)
		{
			List<string> files = new List<string>();

			foreach (string directory in directories)
			{
				files.AddRange(Directory.GetFiles(directory));

				string[] dirs = Directory.GetDirectories(directory);

				if (dirs.Length > 0)
					files.AddRange(GetAllFilesInDirectories(dirs));
			}

			return files;
		}

		void ProcessFiles()
		{
			while (mreFilesReady.WaitOne())
			{
				int itemsToProcess = 0;

				do
				{
					PasswordAndFiles passwordAndFiles;

					lock (filesToProcess)
					{
						passwordAndFiles = filesToProcess.Dequeue();
					}

					if (passwordAndFiles.Encrypt)
						EncryptFiles(passwordAndFiles);
					else
						DecryptFiles(passwordAndFiles);

					lock (filesToProcess)
					{
						itemsToProcess = filesToProcess.Count;
					}

				} while (itemsToProcess > 0);

				mreFilesReady.Reset();

				totalFiles = 0;
				counter = 0;

				if (AllWorkFinished != null)
					AllWorkFinished();
			}
		}

		void EncryptFiles(PasswordAndFiles passwordAndFiles)
		{
			foreach (string file in passwordAndFiles.Files)
			{
				try
				{
					if (FileStarted != null)
						FileStarted(file);

					// Perform a seperate encryption function to encrypt the header information
					EncryptionHeader header = new EncryptionHeader(EncryptionHeaderType.Rijndael, Path.GetFileName(file));

					byte[] headerBytes = header.GetEncryptedHeader(passwordAndFiles.Password);

					string newInputFileName = file;
					string encryptedFileName = file;

					if (!HideFileNames)
					{
						newInputFileName += ".encrypting";

						File.Move(file, newInputFileName);
					}
					else
					{
						encryptedFileName = GetVerifiedUniqueFileName(Path.GetDirectoryName(file) + Path.DirectorySeparatorChar + DataSafeFileNamePrefix + "[0]" + DataSafeFileExtension);
					}

					using (FileStream inputFile = File.Open(newInputFileName, FileMode.Open, FileAccess.Read, FileShare.None))
					{
						using (FileStream outputFile = File.Open(encryptedFileName, FileMode.CreateNew, FileAccess.Write, FileShare.None))
						{
							StreamEncryption(headerBytes, inputFile, outputFile, passwordAndFiles.Password);
						}
					}

					SuperDeleteFile(newInputFileName);
				}
				catch (Exception e)
				{
					string logFile = GetVerifiedUniqueFileName(Path.GetDirectoryName(file) + Path.DirectorySeparatorChar + Path.GetFileNameWithoutExtension(file) + "_DataSafeLog.txt");

					StringBuilder sb = new StringBuilder();

					sb.AppendFormat("There was an error encrypting the file: {0}\r\n\r\n", file);
					sb.Append(e.ToString());

					File.WriteAllText(logFile, sb.ToString());
				}
				finally
				{
					counter++;

					if (FileFinished != null)
						FileFinished(file, totalFiles, counter);
				}
			}
		}

		void DecryptFiles(PasswordAndFiles passwordAndFiles)
		{
			foreach (string file in passwordAndFiles.Files)
			{
				try
				{
					if (FileStarted != null)
						FileStarted(file);

					bool decrypted = false;
					bool outputInputTheSame = false;
					string outputFileName = null;

					using (FileStream inputFile = File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
					{
						// Get the header information
						byte[] headerBytes = new byte[EncryptionHeader.TotalHeaderSize];
						inputFile.Read(headerBytes, 0, headerBytes.Length);

						inputFile.Position = 0;

						EncryptionHeader header = new EncryptionHeader(headerBytes, passwordAndFiles.Password);

						if (header.HeaderEncryptionType == EncryptionHeaderType.Rijndael)
						{
							outputFileName = header.GetHeaderDataAsString();

							if (Path.GetFileName(file) == outputFileName)
							{
								// The dest file and source file are the same
								outputInputTheSame = true;
							}

							outputFileName = GetVerifiedUniqueFileName(Path.GetDirectoryName(file) + Path.DirectorySeparatorChar + outputFileName);

							using (FileStream outputFile = File.Open(outputFileName, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
							{
								StreamEncryption(inputFile, outputFile, passwordAndFiles.Password);
								decrypted = true;
							}
						}
					}

					if (decrypted)
					{
						File.Delete(file);

						if (outputInputTheSame && outputFileName != null)
							File.Move(outputFileName, file);
					}

				}
				catch (Exception e)
				{
					string logFile = GetVerifiedUniqueFileName(Path.GetDirectoryName(file) + Path.DirectorySeparatorChar + Path.GetFileNameWithoutExtension(file) + "_DataSafeLog.txt");

					StringBuilder sb = new StringBuilder();

					sb.AppendFormat("There was an error decrypting the file: {0}\r\n", file);
					sb.Append("The most likely cause of this error is an invalid password. \r\n");
					sb.Append("Another likely cause is that the file you were trying to decrypt was not actually encrypted. \r\n");
					sb.Append("This file might also be incorrectly encrypted - using a different encryption method or something. \r\n");
					sb.Append(e.ToString());

					File.WriteAllText(logFile, sb.ToString());
				}
				finally
				{
					counter++;

					if (FileFinished != null)
						FileFinished(file, totalFiles, counter);
				}
			}
		}

		public string EncryptStringToBase64(string data, string password)
		{
			byte[] bytes = UTF8Encoding.UTF8.GetBytes(data);

			BlockEncryption(ref bytes, password, true);

			return Convert.ToBase64String(bytes);
		}

		public string DecryptBase64String(string data, string password)
		{
			byte[] bytes = Convert.FromBase64String(data);

			BlockEncryption(ref bytes, password, false);

			return UTF8Encoding.UTF8.GetString(bytes);
		}

		static internal byte[] GetKeyFromPassword(string password, byte[] salt)
		{
			Rfc2898DeriveBytes derivedPwd = new Rfc2898DeriveBytes(password, salt, passwordIterations);

			return derivedPwd.GetBytes(passwordSize);
		}

		static internal byte[] GetKeyFromPassword(string password, out byte[] salt)
		{
			Rfc2898DeriveBytes derivedPwd = new Rfc2898DeriveBytes(password, passwordSaltSize, passwordIterations);

			salt = derivedPwd.Salt;

			return derivedPwd.GetBytes(passwordSize);
		}

		static internal void BlockEncryption(ref byte[] b, byte[] passwordBytes, byte[] initVector, bool encrypt)
		{
			ICryptoTransform xForm = null;

			// Using a FIPS compliant algorithm
			using (Aes aes = AesCryptoServiceProvider.Create())
			{
				aes.BlockSize = 128;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				using (xForm = encrypt ? aes.CreateEncryptor(passwordBytes, initVector) : aes.CreateDecryptor(passwordBytes, initVector))
				{
					b = xForm.TransformFinalBlock(b, 0, b.Length);
				}
			}
		}

		public byte[] TrimZeros(byte[] bytes)
		{
			int end = bytes.Length - 1;

			for (int i = bytes.Length - 1; i >= 0; i--)
			{
				if (bytes[i] != 0)
				{
					end = i;
					break;
				}
			}

			byte[] output = new byte[end + 1];

			Buffer.BlockCopy(bytes, 0, output, 0, output.Length);

			return output;
		}

		string GetVerifiedUniqueFileName(string fileName)
		{
			if (!File.Exists(fileName))
				return fileName;

			if (fileName.EndsWith(string.Format("]{0}", Path.GetExtension(fileName))))
			{
				// Already has a number... increment it
				string fileNumber = fileName.Substring(fileName.LastIndexOf("[") + 1, fileName.LastIndexOf("]") - fileName.LastIndexOf("[") - 1);

				string newFileName = fileName.Replace(string.Format("[{0}]", fileNumber), string.Format("[{0}]", Convert.ToInt32(fileNumber) + 1));

				return GetVerifiedUniqueFileName(newFileName);
			}

			return GetVerifiedUniqueFileName(Path.GetDirectoryName(fileName) + Path.DirectorySeparatorChar + Path.GetFileNameWithoutExtension(fileName) + "[0]" + Path.GetExtension(fileName));
		}

		void StreamEncryption(Stream inputStream, Stream outputStream, string password)
		{
			StreamEncryption(null, inputStream, outputStream, password);
		}

		void StreamEncryption(byte[] headerInfo, Stream inputStream, Stream outputStream, string password)
		{
			ICryptoTransform xForm = null;

			using (Aes aes = AesCryptoServiceProvider.Create())
			{
				aes.BlockSize = 128;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				using (xForm = headerInfo != null ? aes.CreateEncryptor(GetKeyFromPassword(password), DataSafeIV) : aes.CreateDecryptor(GetKeyFromPassword(password), DataSafeIV))
				{
					if (headerInfo != null)
					{
						// Encryption operation - add the header data first
						outputStream.Write(headerInfo, 0, headerInfo.Length);
					}
					else
					{
						// Decrypting operation - set the input position to the header length
						inputStream.Position = EncryptionHeader.TotalHeaderSize;
					}

					using (CryptoStream cryptoStream = new CryptoStream(outputStream, xForm, CryptoStreamMode.Write))
					{
						long bytesRemaining = inputStream.Length - inputStream.Position;
						int bytesToRead = readBuffer.Length;

						while (bytesRemaining > 0)
						{
							if (bytesRemaining <= readBuffer.Length)
								bytesToRead = (int)bytesRemaining;

							int bytesRead = inputStream.Read(readBuffer, 0, bytesToRead);
							bytesRemaining -= bytesRead;

							cryptoStream.Write(readBuffer, 0, bytesRead);
							cryptoStream.Flush();

							if (BlockFinished != null)
								BlockFinished(inputStream.Length, inputStream.Length - bytesRemaining);
						}
					}
				}
			}
		}

		void SuperDeleteFile(string fileName)
		{
			if (WipeSourceFiles)
			{
				for (int i = 0; i < WipeSourceFilesPasses; i++)
				{
					OverwriteFile(i + 1, WipeSourceFilesPasses, fileName);
				}
			}

			File.Delete(fileName);
		}

		void OverwriteFile(int currentPass, int totalPasses, string fileName)
		{
			File.SetAttributes(fileName, FileAttributes.Normal);

			using (SafeFileHandle handle = CreateFile(fileName, (uint)FileAccess.ReadWrite, (uint)FileShare.None, IntPtr.Zero, (uint)FileMode.Open, FILE_FLAG_NO_BUFFERING, IntPtr.Zero))
			{
				using (FileStream fileToOverwrite = new FileStream(handle, FileAccess.Write /*, true*/, 4096))
				{
					// 24 is the RSA-AES CSP
					RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider(new CspParameters(24));

					rng.GetBytes(buffer);

					// Writing more than the file size (unless it comes out to be the exact size of the buffer *n) will mask the original filesize
					long bytesToWrite = fileToOverwrite.Length;
					long originalFileSize = fileToOverwrite.Length;

					while (bytesToWrite > 0)
					{
						fileToOverwrite.Write(buffer, 0, buffer.Length);

						bytesToWrite -= buffer.Length;

						if (WipingSourceFileBlockFinished != null)
							WipingSourceFileBlockFinished(currentPass, totalPasses, originalFileSize, originalFileSize - bytesToWrite);
					}
				}
			}
		}

		internal string GetPasswordFromUi()
		{
			return GetPassword();
		}
	}
}
