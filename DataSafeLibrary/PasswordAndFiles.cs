using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DataSafeLibrary
{
    public class PasswordAndFiles
    {
        string[] files;
        string password;
        bool encrypt;

        public string[] Files
        {
            get { return files; }
            set { files = value; }
        }

        public string Password
        {
            get { return password; }
            set { password = value; }
        }

        public bool Encrypt
        {
            get { return encrypt; }
            set { encrypt = value; }
        }

        public PasswordAndFiles(string password, string[] files, bool encrypt)
        {
            this.password = password;
            this.files = files;
            this.encrypt = encrypt;
        }

        public override bool Equals(object obj)
        {
            if (obj == null) 
                return false;

            if (obj.GetType() != typeof(PasswordAndFiles))
                return false;

            PasswordAndFiles item = obj as PasswordAndFiles;

            if (item.Files.Length != files.Length)
                return false;

            if (item.Password != password)
                return false;

            if (item.Encrypt != encrypt)
                return false;

            lock (this)
            {
                for(int i = 0; i < files.Length; i++)
                {
                    if (files[i] != item.Files[i])
                        return false;
                }
            }

            return true;
        }

        public override int GetHashCode()
        {
            return files.GetHashCode() + password.GetHashCode();
        }
    }
}
