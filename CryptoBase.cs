using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TPLib.Crypto
{
    public class CryptoBase
    {

        /// <summary>
        /// Cryto异常事件
        /// </summary>
        public event CryptoErrorHandler ErrorEvent;


        public void OnCryptoErrorEvent(Exception ex)
        {
            if (ErrorEvent!=null)
            {
                ErrorEvent(ex);
            }
        }
    }
}
