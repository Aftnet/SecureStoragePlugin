using Plugin.SecureStorage.Abstractions;
using System;
using System.Threading;

namespace Plugin.SecureStorage
{
    public static class CrossSecureStorage
    {
#if !NETSTANDARD1_4
        private static Lazy<SecureStorageImplementation> fileSystem = new Lazy<SecureStorageImplementation>(LazyThreadSafetyMode.PublicationOnly);
#endif

        public static bool Supported
        {
            get
            {
#if NETSTANDARD1_4
                return false;
#else
                return true;
#endif
            }
        }

        public static ISecureStorage Current
        {
            get
            {
#if NETSTANDARD1_4
                throw new NotImplementedException();
#else
                return fileSystem.Value;
#endif
            }
        }
    }
}
