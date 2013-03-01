using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DataSafeLibrary
{
    // Data Safe v3.0 Header Layout:
	// | Static Header ID | Version | Init Vector  | Password Salt | Header Length | Original Modification Date | Original Filename Size | Original Filename |
	// |     10 bytes     | 2 bytes |    16 bytes  |    8 bytes    |    2 bytes    |          8 bytes           |		1 byte			 |     variable      |
	// |							Unencrypted									   |							Encrypted								     |
	
    public class EncryptionHeader
    {
		static readonly byte[] staticHeaderId = new byte[] { 6, 6, 6, 1, 1, 1, 3, 3, 3, 5 };
		static readonly byte[] applicationVersion = new byte[] { 3, 0 };

		static readonly int unencryptedHeaderLength =
			HeaderInfo.StaticHeaderIdSize +
			HeaderInfo.VersionSize +
			HeaderInfo.IvSize +
			HeaderInfo.PasswordSaltSize +
			HeaderInfo.HeaderLengthSize;

		byte[] passwordSalt;

		public static int UnencryptedHeaderLength
        {
			get { return unencryptedHeaderLength; }
        }

		public string OriginalFileName { get; private set; }
		public DateTime OriginalModificationDate { get; private set; }
		public byte[] InitializationVector { get; private set; }		

		public byte[] PasswordSalt
		{
			get { return passwordSalt; }
			private set { passwordSalt = value; }
		}

		/// <summary>
		/// [Encryption Operations] Create new EncryptionHeader bytes from the passed parameters
		/// </summary>
		public EncryptionHeader(string originalFileName, DateTime originalModificationDate)
		{
			if (string.IsNullOrEmpty(originalFileName))
				throw new ArgumentNullException("originalFileName");

			OriginalFileName = originalFileName;
			OriginalModificationDate = originalModificationDate;
		}

        /// <summary>
		/// [Decryption Operations] Create a new EncryptionHeader class from the specified bytes (encrypted file) and password
        /// </summary>
        public EncryptionHeader(Stream header, string password)
        {
            if (header.Length < unencryptedHeaderLength)
				throw new ArgumentException("header is too short");

			BinaryReader binaryReader = new BinaryReader(header);

			// Make sure the file we're trying to open is the right type
			if (CheckFileType(binaryReader))
			{
				// Now that we're sure we have a valid file type, do we have a password to use to decrypt the encrypted header?
				if (!string.IsNullOrEmpty(password))
				{
					// Get the initialization vector
					InitializationVector = binaryReader.ReadBytes(HeaderInfo.IvSize);

					// Get the password salt
					PasswordSalt = binaryReader.ReadBytes(HeaderInfo.PasswordSaltSize);

					// Get the length of the remaining encrypted header
					ushort encryptedHeaderLength = (ushort)(binaryReader.ReadUInt16() - HeaderInfo.EncryptedHeaderPosition);

					if (encryptedHeaderLength <= 0)
						throw new InvalidOperationException("Header length is invalid");

					// Using the IV, salt and password, get the password derived bytes
					byte[] passwordBytes = Encryption.GetKeyFromPassword(password, PasswordSalt);

					// Pull out the remaining encrypted header
					byte[] encryptedHeader = binaryReader.ReadBytes(encryptedHeaderLength);

					// Decrypt the remaining encrypted header
					Encryption.BlockEncryption(ref encryptedHeader, passwordBytes, InitializationVector, false);

					// Get the original modification date
					long originalModificationDateInTicks = BitConverter.ToInt64(encryptedHeader, HeaderInfo.OriginalModificationDatePosition);
					OriginalModificationDate = DateTime.FromBinary(originalModificationDateInTicks);

					byte originalFileNameLength = encryptedHeader[HeaderInfo.OriginalFileNameLengthPosition];

					// Pull out the decrypted original file name
					byte[] originalFileName = new byte[originalFileNameLength];
					Buffer.BlockCopy(encryptedHeader, HeaderInfo.OriginalFileNamePosition, originalFileName, 0, originalFileNameLength);

					OriginalFileName = ASCIIEncoding.ASCII.GetString(originalFileName);
				}
			}
			else
			{
				throw new InvalidOperationException("Invalid DataSafe header");
			}
        }

		/// <summary>
		/// Create a byte array containing the encryption header with specified parameters
		/// </summary>
		public byte[] Create(byte[] initilizationVector, string password)
		{
			if (string.IsNullOrEmpty(password))
				throw new ArgumentNullException("password");

			if (initilizationVector.Length != HeaderInfo.IvSize)
				throw new ArgumentException("field is incorrect length", "initilizationVector");

			InitializationVector = initilizationVector;
			
			int fileNameLength = ASCIIEncoding.ASCII.GetByteCount(OriginalFileName);

			if(fileNameLength > 255)
				throw new NotSupportedException("Original file name must be fewer than 255 characters in length");

			// Create the byte array with values to be encrypted
			byte[] encryptedValues = new byte[HeaderInfo.OriginalModificationDateSize + HeaderInfo.OriginalFileNameLengthSize + fileNameLength];

			// Copy the modification date in
			Buffer.BlockCopy(BitConverter.GetBytes(OriginalModificationDate.ToBinary()), 0, encryptedValues, 0, HeaderInfo.OriginalModificationDateSize);

			// Set the file name length
			encryptedValues[HeaderInfo.OriginalModificationDateSize] = (byte)fileNameLength;

			// Copy the file name in
			Buffer.BlockCopy(ASCIIEncoding.ASCII.GetBytes(OriginalFileName), 0, encryptedValues, HeaderInfo.OriginalModificationDateSize + 1, fileNameLength);

			// Using the IV, salt and password, get the password derived bytes
			byte[] passwordBytes = Encryption.GetKeyFromPassword(password, out passwordSalt);

			// Encrypt this portion of the header
			Encryption.BlockEncryption(ref encryptedValues, passwordBytes, InitializationVector, true);

			// Create the main header array
			byte[] header = new byte[unencryptedHeaderLength + encryptedValues.Length];

			// Put in the static header id
			Buffer.BlockCopy(staticHeaderId, 0, header, HeaderInfo.StaticHeaderIdPosition, HeaderInfo.StaticHeaderIdSize);

			// Put the version in
			Buffer.BlockCopy(applicationVersion, 0, header, HeaderInfo.VersionPosition, HeaderInfo.VersionSize);

			// Put the IV in
			Buffer.BlockCopy(InitializationVector, 0, header, HeaderInfo.IvPosition, HeaderInfo.IvSize);

			// Put the password salt in
			Buffer.BlockCopy(PasswordSalt, 0, header, HeaderInfo.PasswordSaltPosition, HeaderInfo.PasswordSaltSize);

			// Put the header length in
			Buffer.BlockCopy(BitConverter.GetBytes(header.Length), 0, header, HeaderInfo.HeaderLengthPosition, HeaderInfo.HeaderLengthSize);

			// Tack on the encrypted part of the header
			Buffer.BlockCopy(encryptedValues, 0, header, HeaderInfo.EncryptedHeaderPosition, encryptedValues.Length);

			return header;
		}

		public static bool CheckFileType(BinaryReader headerStream)
		{
			byte[] staticHeaderBytes = headerStream.ReadBytes(HeaderInfo.StaticHeaderIdSize);

			// Compare the static header id on the file with the one in the app
			if (!CompareArrays(staticHeaderId, staticHeaderBytes))
				return false;

			byte[] versionBytes = headerStream.ReadBytes(HeaderInfo.VersionSize);

			// Verify the header version matches the app version
			if (!CompareArrays(applicationVersion, versionBytes))
				return false;

			return true;
		}      

		public static bool CheckFileType(byte[] headerBytes)
		{
			using (MemoryStream ms = new MemoryStream(headerBytes))
			{
				using (BinaryReader br = new BinaryReader(ms))
				{
					return CheckFileType(br);
				}
			}			
		}        		

        static bool CompareArrays(byte[] array1, byte[] array2)
        {
            if (array1.Length != array2.Length)
                return false;

            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i])
                    return false;
            }

            return true;
        }
    }
}
