using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DataSafeLibrary
{
    // Data Safe v3.0 Header Layout:
	// | Static Header ID | Version | Init Vector | Password Salt | Header Length | Original Filename | Original Modification Date |
	// |     10 bytes     | 2 bytes |    8 bytes  |    8 bytes    |    2 bytes    |     255 bytes     |          8 bytes           |
	// |                  Unencrypted											  |				Encrypted						   |

	public class HeaderInfo
	{
		public const int StaticHeaderIdPosition = 0;
		public const int StaticHeaderIdSize = 10;

		public const int VersionPosition = StaticHeaderIdPosition + StaticHeaderIdSize;
		public const int VersionSize = 2;

		public const int IvPosition = VersionPosition + VersionSize;
		public const int IvSize = 8;

		public const int PasswordSaltPosition = IvPosition + IvSize;
		public const int PasswordSaltSize = 8;

		public const int HeaderLengthPosition = PasswordSaltPosition + PasswordSaltSize;
		public const int HeaderLengthSize = 2;

		public const int OriginalFileNamePosition = HeaderLengthPosition + HeaderLengthSize;
		public const int OriginalFileNameSize = 255;

		public const int OriginalModificationDatePosition = OriginalFileNamePosition + OriginalFileNameSize;
		public const int OriginalModificationDateSize = 8;
	}

    public class EncryptionHeader
    {
		static readonly byte[] staticHeaderId = new byte[] { 6, 6, 6, 1, 1, 1, 3, 3, 3, 5 };
		static readonly byte[] applicationVersion = new byte[] { 3, 0 };

        static readonly int unencryptedHeaderLength = 22;

		public static int UnencryptedHeaderLength
        {
			get { return unencryptedHeaderLength; }
        }

		public string OriginalFileName { get; set; }
		public DateTime OriginalModificationDate { get; set; }

        /// <summary>
        /// Create a new EncryptionHeader class from the specified bytes and password
        /// </summary>
        public EncryptionHeader(byte[] headerBytes, string password)
        {
            if (headerBytes.Length < unencryptedHeaderLength)
                throw new ArgumentException("headerBytes is too short");

			// Make sure the file we're trying to open is the right type
			if (CheckFileType(headerBytes))
			{
				// Now that we're sure we have a valid file type, do we have a password to use to decrypt the encrypted header?
				if (!string.IsNullOrEmpty(password))
				{
					// Get the length of the remaining encrypted header
					ushort encryptedHeaderLength = BitConverter.ToUInt16(headerBytes, HeaderInfo.HeaderLengthPosition);

					if (encryptedHeaderLength == 0)
						throw new InvalidOperationException("Header length is invalid");

					// Get the initialization vector
					byte[] initVector = new byte[HeaderInfo.IvSize];
					Buffer.BlockCopy(headerBytes, HeaderInfo.IvPosition, initVector, 0, HeaderInfo.IvSize);

					// Get the password salt
					byte[] passwordSalt = new byte[HeaderInfo.PasswordSaltSize];
					Buffer.BlockCopy(headerBytes, HeaderInfo.PasswordSaltPosition, passwordSalt, 0, HeaderInfo.PasswordSaltSize);

					// Using the IV, salt and password, get the password derived bytes
					byte[] passwordBytes = Encryption.GetKeyFromPassword(password, passwordSalt);

					// Pull out the remaining encrypted header
					byte[] encryptedHeader = new byte[encryptedHeaderLength];
					Buffer.BlockCopy(headerBytes, HeaderInfo.OriginalFileNamePosition, encryptedHeader, 0, encryptedHeaderLength);

					// Decrypt the remaining encrypted header
					Encryption.BlockEncryption(ref encryptedHeader, passwordBytes, initVector, false);

					// Pull out the decrypted original file name
					byte[] originalFileName = new byte[HeaderInfo.OriginalFileNameSize];
					Buffer.BlockCopy(encryptedHeader, 0, originalFileName, 0, HeaderInfo.OriginalFileNameSize);

					OriginalFileName = ASCIIEncoding.ASCII.GetString(originalFileName);

					long originalModificationDateInTicks = BitConverter.ToInt64(encryptedHeader, HeaderInfo.OriginalFileNameSize);

					OriginalModificationDate = DateTime.FromBinary(originalModificationDateInTicks);					
				}
			}
        }

		public static bool CheckFileType(byte[] headerBytes)
		{
			byte[] staticHeaderBytes = new byte[HeaderInfo.StaticHeaderIdSize];
			Buffer.BlockCopy(headerBytes, HeaderInfo.StaticHeaderIdPosition, staticHeaderBytes, 0, HeaderInfo.StaticHeaderIdSize);

			// Compare the static header id on the file with the one in the app
			if (!CompareArrays(staticHeaderId, staticHeaderBytes))
				return false;

			byte[] versionBytes = new byte[HeaderInfo.VersionSize];
			Buffer.BlockCopy(headerBytes, HeaderInfo.VersionPosition, versionBytes, 0, HeaderInfo.VersionSize);

			// Verify the header version matches the app version
			if (!CompareArrays(applicationVersion, versionBytes))
				return false;

			return true;
		}        

        public EncryptionHeader(EncryptionHeaderType headerType, string headerPayload)
            : this(headerType, UTF8Encoding.UTF8.GetBytes(headerPayload))
        {        
        }

        public EncryptionHeader(EncryptionHeaderType headerType, byte[] headerPayload)
        {
            if (headerPayload.Length > unencryptedDataLength)
                throw new ArgumentException("headerPayload is too large.");

            int len = headerPayload.Length;

            if (len > unencryptedDataLength)
                len = unencryptedDataLength;

            Buffer.BlockCopy(headerPayload, 0, headerData, 0, len);
            this.headerEncryptionType = headerType;
        }       

        public byte[] GetEncryptedHeader(string password)
        {
            byte[] encryptedHeaderData = Encryption.Instance.TrimZeros(headerData);
            byte[] completeHeader = new byte[TotalHeaderSize];

            Encryption.Instance.BlockEncryption(ref encryptedHeaderData, password, true);              
            
            // Copy the aes encryption id in
            Buffer.BlockCopy(EncryptionTypes.AesEncryptionId, 0, completeHeader, 0, EncryptionTypes.AesEncryptionId.Length);

            // Copy the actual header in
            Buffer.BlockCopy(encryptedHeaderData, 0, completeHeader, EncryptionTypes.AesEncryptionId.Length, encryptedHeaderData.Length);

            return completeHeader;            
        }

        public string GetHeaderDataAsString()
        {
            return UTF8Encoding.UTF8.GetString(Encryption.Instance.TrimZeros(headerData));
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
