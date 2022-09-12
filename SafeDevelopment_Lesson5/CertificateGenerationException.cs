using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SafeDevelopment_Lesson5
{
    public class CertificateGenerationException : Exception
    {
        public CertificateGenerationException(string message)
            : base(message)
        {

        }
    }
}
