using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace HashPassword
{
    class Program
    {
        static void Main(string[] args)
        {
            string ConnectionString = @"Data Source=DESKTOP-1ULGF16;Initial Catalog=db_SavannaERP;User ID=sa;Password=sa@123; Pooling=true;Max Pool Size=32700;";
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                List<UserInfo> userInfos = new List<UserInfo>();
                string MyTmp = $"SELECT userName,password FROM tblTempUser;";
                SqlCommand Mycmd = new SqlCommand(MyTmp, connection);
                string userName = "";
                string password = "";
                using (var reader = Mycmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        userName = reader.GetString(0);

                        password = reader.GetString(1);
                        string hashPassword = HashPassword(password);
                        var user = new UserInfo
                        {
                            userName=userName,
                            password= hashPassword
                        };
                        userInfos.Add(user);
                    }
                }
                foreach(var data in userInfos)
                {
                    string Tmp1 = $"UPDATE tblTempUser SET passwordHash = '{data.password}' WHERE userName = '{data.userName}';";
                    Mycmd = new SqlCommand(Tmp1, connection);
                    Mycmd.ExecuteScalar();
                }
                //string hashPassword = HashPasswordSalt(password);
                

            }
            Console.WriteLine("Success");
        }
        
        static string HashPassword(string password)
        {
            byte[] salt;
            byte[] buffer2;
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, 0x10, 0x3e8))
            {
                salt = bytes.Salt;
                buffer2 = bytes.GetBytes(0x20);
            }
            byte[] dst = new byte[0x31];
            Buffer.BlockCopy(salt, 0, dst, 1, 0x10);
            Buffer.BlockCopy(buffer2, 0, dst, 0x11, 0x20);
            return Convert.ToBase64String(dst);
        }
        private const int SaltByteSize = 24;
        private const int HashByteSize = 24;
        private const int HasingIterationsCount = 10101;


        public static string HashPasswordSalt(string password)
        {
            // http://stackoverflow.com/questions/19957176/asp-net-identity-password-hashing

            byte[] salt;
            byte[] buffer2;
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, SaltByteSize, HasingIterationsCount))
            {
                salt = bytes.Salt;
                buffer2 = bytes.GetBytes(HashByteSize);
            }
            byte[] dst = new byte[(SaltByteSize + HashByteSize) + 1];
            Buffer.BlockCopy(salt, 0, dst, 1, SaltByteSize);
            Buffer.BlockCopy(buffer2, 0, dst, SaltByteSize + 1, HashByteSize);
            return Convert.ToBase64String(dst);
        }

        public static bool VerifyHashedPassword(string hashedPassword, string password)
        {
            byte[] _passwordHashBytes;

            int _arrayLen = (SaltByteSize + HashByteSize) + 1;

            if (hashedPassword == null)
            {
                return false;
            }

            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            byte[] src = Convert.FromBase64String(hashedPassword);

            if ((src.Length != _arrayLen) || (src[0] != 0))
            {
                return false;
            }

            byte[] _currentSaltBytes = new byte[SaltByteSize];
            Buffer.BlockCopy(src, 1, _currentSaltBytes, 0, SaltByteSize);

            byte[] _currentHashBytes = new byte[HashByteSize];
            Buffer.BlockCopy(src, SaltByteSize + 1, _currentHashBytes, 0, HashByteSize);

            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, _currentSaltBytes, HasingIterationsCount))
            {
                _passwordHashBytes = bytes.GetBytes(SaltByteSize);
            }

            return AreHashesEqual(_currentHashBytes, _passwordHashBytes);

        }

        private static bool AreHashesEqual(byte[] firstHash, byte[] secondHash)
        {
            int _minHashLength = firstHash.Length <= secondHash.Length ? firstHash.Length : secondHash.Length;
            var xor = firstHash.Length ^ secondHash.Length;
            for (int i = 0; i < _minHashLength; i++)
                xor |= firstHash[i] ^ secondHash[i];
            return 0 == xor;
        }

        private class UserInfo
        {
            public string userName { get; set; }
            public string password { get; set; }
        }

    }

    

}
