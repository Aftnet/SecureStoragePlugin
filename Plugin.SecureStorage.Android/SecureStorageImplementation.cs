using Android.Content;
using Android.Preferences;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using Plugin.SecureStorage.Abstractions;
using System;
using System.Linq;
using System.Text;

namespace Plugin.SecureStorage
{
    internal class SecureStorageImplementation : ISecureStorage
    {
        private const string AndroidKeyStoreProviderName = "AndroidKeyStore";
        private const string KeyAlias = "SecureStoragePluginKey";

        private static readonly Lazy<IKey> EncryptionKey = new Lazy<IKey>(GetEncryptionKey);
        private static readonly byte[] EncryptionIV = Enumerable.Repeat(default(byte), 128).ToArray();

        #region ISecureStorageImplementation

        /// <summary>
        /// Retrieves the value from storage.
        /// If value with the given key does not exist,
        /// returns default value
        /// </summary>
        /// <returns>The value.</returns>
        /// <param name="key">Key.</param>
        /// <param name="defaultValue">Default value.</param>
        public string GetValue(string key, string defaultValue)
        {
            using (var preferences = GetPreferences())
            {
                return preferences.GetString(key, defaultValue);
            }
        }

        /// <summary>
        /// Sets the value for the given key. If value exists, overwrites it
        /// Else creates new entry.
        /// Does not accept null value.
        /// </summary>
        /// <returns>true</returns>
        /// <c>false</c>
        /// <param name="key">Key.</param>
        /// <param name="value">Value.</param>
        public bool SetValue(string key, string value)
        {
            using (var preferences = GetPreferences())
            using (var editor = preferences.Edit())
            {
                try
                {
                    editor.PutString(key, value);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Deletes the key and corresponding value from the storage
        /// </summary>
        public bool DeleteKey(string key)
        {
            using (var preferences = GetPreferences())
            using (var editor = preferences.Edit())
            {
                try
                {
                    editor.Remove(key);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Determines whether specified key exists in the storage
        /// </summary>
        public bool HasKey(string key)
        {
            using (var preferences = GetPreferences())
            {
                return preferences.Contains(key);
            }
        }

        #endregion
        private static ISharedPreferences GetPreferences()
        {
            return PreferenceManager.GetDefaultSharedPreferences(Android.App.Application.Context);
        }


        private static IKey GetEncryptionKey()
        {
            IKey output = null;

            var store = KeyStore.GetInstance(AndroidKeyStoreProviderName);
            store.Load(null);

            if (store.ContainsAlias(KeyAlias))
            {
                output = store.GetKey(KeyAlias, null);
            }
            else
            {
                var generator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, AndroidKeyStoreProviderName);
                generator.Init(new KeyGenParameterSpec.Builder(KeyAlias, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                    .SetBlockModes(KeyProperties.BlockModeGcm).SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
                    .SetRandomizedEncryptionRequired(false).Build());
                output = generator.GenerateKey();
            }

            return output;
        }

        private static Cipher GetCipher(CipherMode mode)
        {
            var output = Cipher.GetInstance("AES/GCM/NoPadding");
            output.Init(mode, EncryptionKey.Value, new GCMParameterSpec(128, EncryptionIV));
            return output;
        }

        private static string EncryptString(string plainText)
        {
            var cipher = GetCipher(CipherMode.EncryptMode);

            var buffer = Encoding.UTF8.GetBytes(plainText);
            buffer = cipher.DoFinal(buffer);

            var output = Convert.ToBase64String(buffer);
            return output;
        }

        private static string DecryptString(string cipherText)
        {
            var cipher = GetCipher(CipherMode.DecryptMode);

            var buffer = Convert.FromBase64String(cipherText);
            buffer = cipher.DoFinal(buffer);

            var output = Encoding.UTF8.GetString(buffer);
            return output;
        }
    }
}