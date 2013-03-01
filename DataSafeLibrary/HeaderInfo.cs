
namespace DataSafeLibrary
{
	public class HeaderInfo
	{
		public const int StaticHeaderIdPosition = 0;
		public const int StaticHeaderIdSize = 10;

		public const int VersionPosition = StaticHeaderIdPosition + StaticHeaderIdSize;
		public const int VersionSize = 2;

		public const int IvPosition = VersionPosition + VersionSize;
		public const int IvSize = 16;

		public const int PasswordSaltPosition = IvPosition + IvSize;
		public const int PasswordSaltSize = 8;

		public const int HeaderLengthPosition = PasswordSaltPosition + PasswordSaltSize;
		public const int HeaderLengthSize = 2;

		public const ushort EncryptedHeaderPosition = HeaderLengthPosition + HeaderLengthSize;

		// Encrypted header info below - starting at a new index

		public const int OriginalModificationDatePosition = 0;
		public const int OriginalModificationDateSize = 8;

		public const int OriginalFileNameLengthPosition = OriginalModificationDatePosition + OriginalModificationDateSize;
		public const int OriginalFileNameLengthSize = 1;

		public const int OriginalFileNamePosition = OriginalFileNameLengthPosition + OriginalFileNameLengthSize;				
	}
}
