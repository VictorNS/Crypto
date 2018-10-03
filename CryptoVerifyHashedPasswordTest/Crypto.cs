using System;
using System.Text;

namespace CodeVerifyHashedPasswordTest
{
	/*
	* copied from
	* Assembly System.Web.Helpers, Version=3.0.0.0
	* System.Web.Helpers.Crypto
	* public static bool VerifyHashedPassword(string hashedPassword, string password);
	*/
	internal class Crypto
	{
		internal static bool VerifyHashedPassword(string hashedPassword, string password)
		{
			int PBKDF2IterCount = 1000; // default for Rfc2898DeriveBytes
			int PBKDF2SubkeyLength = 256 / 8; // 256 bits
			int SaltSize = 128 / 8; // 128 bits
			if (hashedPassword == null)
			{
				throw new ArgumentNullException("hashedPassword");
			}
			if (password == null)
			{
				throw new ArgumentNullException("password");
			}

			byte[] hashedPasswordBytes = Convert.FromBase64String(hashedPassword);
			Console.WriteLine("hashedPasswordBytes=" + BytesToString(hashedPasswordBytes));

			// Verify a version 0 (see comment above) password hash.

			if (hashedPasswordBytes.Length != (1 + SaltSize + PBKDF2SubkeyLength) || hashedPasswordBytes[0] != 0x00)
			{
				// Wrong length or version header.
				return false;
			}

			byte[] salt = new byte[SaltSize];
			Buffer.BlockCopy(hashedPasswordBytes, 1, salt, 0, SaltSize);
			Console.WriteLine("salt=" + BytesToString(salt));
			byte[] storedSubkey = new byte[PBKDF2SubkeyLength];
			Buffer.BlockCopy(hashedPasswordBytes, 1 + SaltSize, storedSubkey, 0, PBKDF2SubkeyLength);
			Console.WriteLine("storedSubkey=" + BytesToString(storedSubkey));

			byte[] generatedSubkey;
			using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, PBKDF2IterCount))
			{
				Console.WriteLine("Call Rfc2898DeriveBytes with password="+ password + " salt... PBKDF2IterCount="+ PBKDF2IterCount);
				generatedSubkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
				Console.WriteLine("generatedSubkey=" + BytesToString(generatedSubkey));
			}
			Console.WriteLine();
			Console.WriteLine("Totaly compare:");
			Console.WriteLine("   storedSubkey=" + BytesToString(storedSubkey));
			Console.WriteLine("generatedSubkey=" + BytesToString(generatedSubkey));
			return ByteArraysEqual(storedSubkey, generatedSubkey);
		}

		private static bool ByteArraysEqual(byte[] a, byte[] b)
		{
			if (ReferenceEquals(a, b))
			{
				return true;
			}

			if (a == null || b == null || a.Length != b.Length)
			{
				return false;
			}

			bool areSame = true;
			for (int i = 0; i < a.Length; i++)
			{
				areSame &= (a[i] == b[i]);
			}
			return areSame;
		}

		private static string BytesToString(byte[] source)
		{
			var sb = new StringBuilder();
			foreach (var b in source)
			{
				sb.Append(b.ToString());
				sb.Append(' ');
			}
			return sb.ToString();
		}

	}
}
