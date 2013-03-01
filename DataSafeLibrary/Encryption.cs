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
using System.Threading.Tasks;

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

		static readonly Settings settings = new Settings();

		static readonly int passwordIterations = 1000;
		static readonly int passwordSaltSize = 8;
		static readonly int passwordSize = 16;

		static readonly string dataSafeFileNamePrefix = "DataSafe";
		static readonly string dataSafeFileExtension = ".enc";

		byte[] readBuffer;
		byte[] writeBuffer;

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

		Queue<PasswordAndFiles> filesToProcess = new Queue<PasswordAndFiles>();

		int counter = 0;
		int totalFiles;
		ManualResetEvent mreFilesReady = new ManualResetEvent(false);
		Thread processThread;

		static object lockObject = new object();
		static Encryption instance;
		IDataSafeInterface dataSafeInterface = new DataSafeInterface();

		ServiceHost host;

		public IDataSafeInterface DataSafeInterface
		{
			get { return dataSafeInterface; }
			set { dataSafeInterface = value; }
		}

		public static Encryption Instance
		{
			get 
			{
				if (instance == null)
				{
					lock (lockObject)
					{
						if (instance == null)
						{
							instance = new Encryption();
						}
					}
				}

				return instance;
			}
		}

		Encryption()
		{
			readBuffer = new byte[settings.ReadBufferSizeInBytes];
			writeBuffer = new byte[settings.WriteBufferSizeInBytes];

			StartDataSafeInterfaceService();

			processThread = new Thread(ProcessFiles);
			processThread.IsBackground = true;
			processThread.Start();
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
		
		public string[] GetFilesOfType(string[] files, bool encrypted)
		{
			files = ReplaceDirectoriesWithFiles(files);

			List<string> returnedFiles = new List<string>();

			foreach (string file in files)
			{
				try
				{
					using (FileStream inputFile = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
					{
						bool fileCheckResult = EncryptionHeader.CheckFileType(new BinaryReader(inputFile));

						if (encrypted && fileCheckResult)
							returnedFiles.Add(file);
						else if (!encrypted && !fileCheckResult)
							returnedFiles.Add(file);
					}
				}
				catch
				{
					// Skip this file
				}
			}

			return returnedFiles.ToArray();
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

		private void ReplaceDirectoriesWithFiles(PasswordAndFiles passwordAndFiles)
		{
			passwordAndFiles.Files = ReplaceDirectoriesWithFiles(passwordAndFiles.Files);
		}

		private string[] ReplaceDirectoriesWithFiles(string[] oldFiles)
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

		private List<string> GetAllFilesInDirectories(string[] directories)
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

		private void ProcessFiles()
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

		private void EncryptFiles(PasswordAndFiles passwordAndFiles)
		{
			foreach (string file in passwordAndFiles.Files)
			{
				try
				{
					if (FileStarted != null)
						FileStarted(file);

					FileInfo fileInfo = new FileInfo(file);

					// Perform a seperate encryption function to encrypt the header information
					EncryptionHeader header = new EncryptionHeader(Path.GetFileName(file), fileInfo.LastWriteTime);

					// Create an IV
					byte[] iv = new byte[HeaderInfo.IvSize];
					RNGCryptoServiceProvider.Create().GetBytes(iv);

					byte[] headerBytes = header.Create(iv, passwordAndFiles.Password);

					string newInputFileName = file;
					string encryptedFileName = file;

					encryptedFileName = GetVerifiedUniqueFileName(string.Format("{0}{1}{2}[0]{3}", Path.GetDirectoryName(file), Path.DirectorySeparatorChar, dataSafeFileNamePrefix, dataSafeFileExtension));

					using (FileStream inputFile = File.Open(newInputFileName, FileMode.Open, FileAccess.Read, FileShare.None))
					{
						using (FileStream outputFile = File.Open(encryptedFileName, FileMode.CreateNew, FileAccess.Write, FileShare.None))
						{							
							StreamEncryption(headerBytes, inputFile, outputFile, GetKeyFromPassword(passwordAndFiles.Password, header.PasswordSalt), header.InitializationVector);
						}
					}

					// Try to wipe the file
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

		private void DecryptFiles(PasswordAndFiles passwordAndFiles)
		{
			foreach (string file in passwordAndFiles.Files)
			{
				try
				{
					if (FileStarted != null)
						FileStarted(file);

					bool decrypted = false;
					bool sourceSameAsDest = false;
					string outputFileName;

					using (FileStream inputFile = File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
					{
						// Get the header information
						EncryptionHeader header = new EncryptionHeader(inputFile, passwordAndFiles.Password);
						outputFileName = header.OriginalFileName;

						// Are the destination file and source file the same?  If so, flag it.
						sourceSameAsDest = Path.GetFileName(file) == outputFileName;

						// This is here in case they have another file in this directory that has the same name as the soon-to-be-decrypted file.
						outputFileName = GetVerifiedUniqueFileName(string.Format("{0}{1}{2}", Path.GetDirectoryName(file), Path.DirectorySeparatorChar, outputFileName));

						using (FileStream outputFile = File.Open(outputFileName, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
						{
							StreamEncryption(inputFile, outputFile, GetKeyFromPassword(passwordAndFiles.Password, header.PasswordSalt), header.InitializationVector);

							// Double-checking to make sure we got through the decryption so we don't delete anything otherwise...
							// This shouldn't be necessary, but it's here anyway :)
							decrypted = true;
						}
					}

					if (decrypted)
					{
						// Do a simple delete on the encrypted file... no point in wiping it.
						File.Delete(file);

						if (sourceSameAsDest && outputFileName != null)
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

		internal static byte[] GetKeyFromPassword(string password, byte[] salt)
		{
			Rfc2898DeriveBytes derivedPwd = new Rfc2898DeriveBytes(password, salt, passwordIterations);

			return derivedPwd.GetBytes(passwordSize);
		}

		internal static byte[] GetKeyFromPassword(string password, out byte[] salt)
		{
			Rfc2898DeriveBytes derivedPwd = new Rfc2898DeriveBytes(password, passwordSaltSize, passwordIterations);

			salt = derivedPwd.Salt;

			return derivedPwd.GetBytes(passwordSize);
		}

		internal static void BlockEncryption(ref byte[] b, byte[] passwordBytes, byte[] initVector, bool encrypt)
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

		private string GetVerifiedUniqueFileName(string fileName)
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

		private void StreamEncryption(Stream inputStream, Stream outputStream, byte[] password, byte[] iv)
		{
			StreamEncryption(null, inputStream, outputStream, password, iv);
		}

		private void StreamEncryption(byte[] headerInfo, Stream inputStream, Stream outputStream, byte[] password, byte[] iv)
		{
			ICryptoTransform xForm = null;

			using (Aes aes = AesCryptoServiceProvider.Create())
			{
				aes.BlockSize = 128;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				using (xForm = headerInfo != null ? aes.CreateEncryptor(password, iv) : aes.CreateDecryptor(password, iv))
				{
					if (headerInfo != null)
					{
						// Encryption operation - add the header data first
						outputStream.Write(headerInfo, 0, headerInfo.Length);
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

		public static void EncryptDecryptCTR(Stream inputStream, Stream outputStream, byte[] iv, byte[] password)
		{
			using (Aes cryptoProvider = AesCryptoServiceProvider.Create())
			{
				cryptoProvider.Mode = CipherMode.ECB;
				cryptoProvider.Padding = PaddingMode.None; // no padding in CTR
				cryptoProvider.Key = password;
				int blockSizeInBytes = cryptoProvider.BlockSize / 8;

				using (ICryptoTransform encryptor = cryptoProvider.CreateEncryptor(cryptoProvider.Key, cryptoProvider.IV))
				{
					Parallel.For(0L, inputStream.Length / blockSizeInBytes + 1, counter =>
					{
						byte[] oneTimePad = new byte[blockSizeInBytes];
						encryptor.TransformBlock(iv.Concat(BitConverter.GetBytes(counter)).ToArray(), 0, blockSizeInBytes, oneTimePad, 0);

						int position = (int)counter * blockSizeInBytes;

						byte[] xOrArray = new byte[blockSizeInBytes];
						inputStream.Read(xOrArray, position, blockSizeInBytes);

						byte[] xOrd = Xor2Arrays(xOrArray, position, oneTimePad);

						outputStream.Write(xOrd, position, xOrd.Length);
					});
				}
			}
		}

		public static byte[] Xor2Arrays(byte[] array1, int position, byte[] array2)
		{
			int size = Math.Min(array1.Length - position, array2.Length);
			byte[] result = new byte[size];

			for (int i = 0; i < size; i++)
			{
				result[i] = (byte)(array1[position + i] ^ array2[i]);
			}

			return result;
		}

		private void SuperDeleteFile(string fileName)
		{
			if (settings.MakeSourceUnrecoverable)
			{
				for (int i = 0; i < settings.WipeSourceFilesPasses; i++)
				{
					OverwriteFile(i + 1, settings.WipeSourceFilesPasses, fileName);
				}
			}

			File.Delete(fileName);
		}

		private void OverwriteFile(int currentPass, int totalPasses, string fileName)
		{
			File.SetAttributes(fileName, FileAttributes.Normal);

			using (SafeFileHandle handle = CreateFile(fileName, (uint)FileAccess.ReadWrite, (uint)FileShare.None, IntPtr.Zero, (uint)FileMode.Open, FILE_FLAG_NO_BUFFERING, IntPtr.Zero))
			{
				using (FileStream fileToOverwrite = new FileStream(handle, FileAccess.Write /*, true*/, 4096))
				{
					// 24 is the RSA-AES CSP
					RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider(new CspParameters(24));

					rng.GetBytes(writeBuffer);

					// Writing more than the file size (unless it comes out to be the exact size of the buffer *n) will mask the original filesize
					long bytesToWrite = fileToOverwrite.Length;
					long originalFileSize = fileToOverwrite.Length;

					while (bytesToWrite > 0)
					{
						fileToOverwrite.Write(writeBuffer, 0, writeBuffer.Length);

						bytesToWrite -= writeBuffer.Length;

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
