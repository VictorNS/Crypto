using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeVerifyHashedPasswordTest
{
	class Program
	{
		static void Main(string[] args)
		{
			var check = Crypto.VerifyHashedPassword("ABzXvbrJoJyfvhK5U5hoG/SoV1w0XiP4+uUpNm7Ru5991Occ9/LHyekyHhFgf/IHCg==", "1234");
			Console.WriteLine();
			Console.WriteLine($"Main result={check}");
		}
	}
}
