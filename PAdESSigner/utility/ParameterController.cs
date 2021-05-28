using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace utility
{
    class ParameterController
    {
        private List<string> _parameterList;
        private Dictionary<string, string> _libraryParameter;

        /**
		 * The class constructor
		 * @param args The string input argument from main class
		 * @throws Exception
		 */
        public ParameterController(string[] args)
        {
			Console.WriteLine("Intializing library parameter...");
			_libraryParameter = new Dictionary<string, string>();
			_parameterList = new List<string> {  };
			GenerateParameter(args);
		}

		/**
		 * Generate parameter from input parameter
		 * @param args The string input argument from main class
		 * @throws Exception
		 */
		private void GenerateParameter(string[] args)
		{
			if (!ValidateRequireParameter(args)) {
				throw new Exception("Required parameter is missing");
			}

			if (args.Length == 0) {
				throw new Exception("Parameter cannot be blank");
			}
			
			Console.WriteLine("\tParameter list:");
			
			for(int i=0; i<args.Length; i+=2) 
			{
				if (args[i].StartsWith("-"))
				{
					Console.WriteLine("\t\t" + args[i].ToString().Trim() + ": " + args[i + 1].ToString().Trim());
					try
                    {
						string value = System.Text.Encoding.UTF8.GetString(System.Text.Encoding.Default.GetBytes(args[i + 1]));
						_libraryParameter.Add(args[i], value);

					} catch (Exception)
                    {
						continue;
                    }
				}
				else
				{
					throw new Exception("Unrecognized paramater type");
				}
			}
		}

		/**
		 * Check required parameter
		 * @param args The string input argument from main class
		 * @return
		 */
		private bool ValidateRequireParameter(string[] args)
		{
			List<string> argsList = args.ToList<string>();
			if (_parameterList.Count == 0)
            {
				return true;
            }

			if (argsList.Intersect(_parameterList).Any())
			{
				Console.WriteLine("\tRequired parameter complete.");
				return true;
			}
			else
			{
				Console.WriteLine("\tRequired parameter incomplete.");
				return false;
			}
		}

		/**
		 * Get library parameter from external input
		 * @param key Parameter key name
		 * @return
		 */
		public string getParameterValue(string key)
		{
			try
			{
				//Console.WriteLine(key + " is " + _libraryParameter[key]);
				return _libraryParameter[key];
			}
			catch (Exception)
            {
				return null;
            }
			
		}
    }
}
