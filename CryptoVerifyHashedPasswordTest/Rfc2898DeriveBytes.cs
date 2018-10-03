using System;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace CodeVerifyHashedPasswordTest
{
	/*
	* copied from
	* Assembly mscorlib, Version=4.0.0.0
	* System.Security.Cryptography.Rfc2898DeriveBytes
	*/

	/// <summary>Implements password-based key derivation functionality, PBKDF2, by using a pseudo-random number generator based on <see cref="T:System.Security.Cryptography.HMACSHA1" />.</summary>
	public class Rfc2898DeriveBytes : IDisposable
	{
		private byte[] m_buffer;

		private byte[] m_salt;

		private HMAC m_hmac;

		private uint m_iterations;

		private uint m_block;

		private int m_startIndex;

		private int m_endIndex;

		private int m_blockSize;

		/// <summary>Gets or sets the number of iterations for the operation.</summary>
		/// <returns>The number of iterations for the operation.</returns>
		/// <exception cref="T:System.ArgumentOutOfRangeException">The number of iterations is less than 1. </exception>
		public int IterationCount
		{
			get
			{
				return (int)m_iterations;
			}
			set
			{
				if (value <= 0)
				{
					throw new ArgumentOutOfRangeException("value", "ArgumentOutOfRange_NeedPosNum");
				}
				m_iterations = (uint)value;
				Initialize();
			}
		}

		/// <summary>Gets or sets the key salt value for the operation.</summary>
		/// <returns>The key salt value for the operation.</returns>
		/// <exception cref="T:System.ArgumentException">The specified salt size is smaller than 8 bytes. </exception>
		/// <exception cref="T:System.ArgumentNullException">The salt is null. </exception>
		public byte[] Salt
		{
			get
			{
				return (byte[])m_salt.Clone();
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				if (value.Length < 8)
				{
					throw new ArgumentException("Cryptography_PasswordDerivedBytes_FewBytesSalt");
				}
				m_salt = (byte[])value.Clone();
				Initialize();
			}
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Security.Cryptography.Rfc2898DeriveBytes" /> class using a password and salt to derive the key.</summary>
		/// <param name="password">The password used to derive the key. </param>
		/// <param name="salt">The key salt used to derive the key. </param>
		/// <exception cref="T:System.ArgumentException">The specified salt size is smaller than 8 bytes or the iteration count is less than 1. </exception>
		/// <exception cref="T:System.ArgumentNullException">The password or salt is null. </exception>
		public Rfc2898DeriveBytes(string password, byte[] salt)
			: this(password, salt, 1000)
		{
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Security.Cryptography.Rfc2898DeriveBytes" /> class using a password, a salt, and number of iterations to derive the key.</summary>
		/// <param name="password">The password used to derive the key. </param>
		/// <param name="salt">The key salt used to derive the key. </param>
		/// <param name="iterations">The number of iterations for the operation. </param>
		/// <exception cref="T:System.ArgumentException">The specified salt size is smaller than 8 bytes or the iteration count is less than 1. </exception>
		/// <exception cref="T:System.ArgumentNullException">The password or salt is null. </exception>
		public Rfc2898DeriveBytes(string password, byte[] salt, int iterations)
			: this(password, salt, iterations, HashAlgorithmName.SHA1)
		{
		}

		public Rfc2898DeriveBytes(string password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithm)
			: this(new UTF8Encoding(false).GetBytes(password), salt, iterations, hashAlgorithm)
		{
		}

		/// <summary>Initializes a new instance of the <see cref="T:System.Security.Cryptography.Rfc2898DeriveBytes" /> class using a password, a salt, and number of iterations to derive the key.</summary>
		/// <param name="password">The password used to derive the key. </param>
		/// <param name="salt">The key salt used to derive the key.</param>
		/// <param name="iterations">The number of iterations for the operation. </param>
		/// <exception cref="T:System.ArgumentException">The specified salt size is smaller than 8 bytes or the iteration count is less than 1. </exception>
		/// <exception cref="T:System.ArgumentNullException">The password or salt is null. </exception>
		public Rfc2898DeriveBytes(byte[] password, byte[] salt, int iterations)
			: this(password, salt, iterations, HashAlgorithmName.SHA1)
		{
		}

		[SecuritySafeCritical]
		public Rfc2898DeriveBytes(byte[] password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithm)
		{
			if (string.IsNullOrEmpty(hashAlgorithm.Name))
			{
				throw new ArgumentException("Cryptography_HashAlgorithmNameNullOrEmpty", "hashAlgorithm");
			}
			HMAC hMAC = HMAC.Create("HMAC" + hashAlgorithm.Name);
			if (hMAC == null)
			{
				throw new CryptographicException("Cryptography_UnknownHashAlgorithm", hashAlgorithm.Name);
			}
			Salt = salt;
			IterationCount = iterations;
			hMAC.Key = password;
			m_hmac = hMAC;
			m_blockSize = hMAC.HashSize >> 3;
			Initialize();
		}

		/// <summary>Returns the pseudo-random key for this object.</summary>
		/// <returns>A byte array filled with pseudo-random key bytes.</returns>
		/// <param name="cb">The number of pseudo-random key bytes to generate. </param>
		/// <exception cref="T:System.ArgumentOutOfRangeException">
		///   <paramref name="cb " />is out of range. This parameter requires a non-negative number.</exception>
		public byte[] GetBytes(int cb)
		{
			if (cb <= 0)
			{
				throw new ArgumentOutOfRangeException("cb", "ArgumentOutOfRange_NeedPosNum");
			}
			byte[] array = new byte[cb];
			int i = 0;
			int num = m_endIndex - m_startIndex;
			if (num > 0)
			{
				if (cb < num)
				{
					Buffer.BlockCopy(m_buffer, m_startIndex, array, 0, cb);
					m_startIndex += cb;
					return array;
				}
				Buffer.BlockCopy(m_buffer, m_startIndex, array, 0, num);
				m_startIndex = (m_endIndex = 0);
				i += num;
			}
			for (; i < cb; i += m_blockSize)
			{
				byte[] src = Func();
				int num2 = cb - i;
				if (num2 <= m_blockSize)
				{
					Buffer.BlockCopy(src, 0, array, i, num2);
					i += num2;
					Buffer.BlockCopy(src, num2, m_buffer, m_startIndex, m_blockSize - num2);
					m_endIndex += m_blockSize - num2;
					return array;
				}
				Buffer.BlockCopy(src, 0, array, i, m_blockSize);
			}
			return array;
		}

		private void Initialize()
		{
			if (m_buffer != null)
			{
				Array.Clear(m_buffer, 0, m_buffer.Length);
			}
			m_buffer = new byte[m_blockSize];
			m_block = 1u;
			m_startIndex = (m_endIndex = 0);
		}

		private byte[] Func()
		{
			byte[] array = Utils_Int(m_block);
			m_hmac.TransformBlock(m_salt, 0, m_salt.Length, null, 0);
			m_hmac.TransformBlock(array, 0, array.Length, null, 0);
			var _EmptyArray_byte_Value = new byte[0]; // EmptyArray<byte>.Value
			m_hmac.TransformFinalBlock(_EmptyArray_byte_Value, 0, 0);
			byte[] hashValue = m_hmac.Hash;
			m_hmac.Initialize();
			byte[] array2 = hashValue;
			for (int i = 2; i <= m_iterations; i++)
			{
				m_hmac.TransformBlock(hashValue, 0, hashValue.Length, null, 0);
				m_hmac.TransformFinalBlock(_EmptyArray_byte_Value, 0, 0);
				hashValue = m_hmac.Hash;
				for (int j = 0; j < m_blockSize; j++)
				{
					array2[j] ^= hashValue[j];
				}
				m_hmac.Initialize();
			}
			m_block++;
			return array2;
		}

		private static byte[] Utils_Int(uint i)
		{
			return new byte[4]
			{
		(byte)(i >> 24),
		(byte)(i >> 16),
		(byte)(i >> 8),
		(byte)i
			};
		}

		public void Dispose()
		{
		}
	}
}