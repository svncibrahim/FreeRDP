/*
   AES-256-GCM encryption helper backed by Android Keystore.

   Encrypted values are stored as Base64( IV[12] || ciphertext ).
   Empty or null strings are passed through unchanged (no encryption).
*/

package com.freerdp.freerdpcore.security;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.KeyStore;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class KeystoreHelper
{
	private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
	private static final String KEY_ALIAS = "afreerdp_bookmark_key";
	private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
	private static final int GCM_IV_LENGTH = 12;
	private static final int GCM_TAG_LENGTH = 128; // bits

	private static volatile KeystoreHelper instance;

	private KeystoreHelper()
	{
	}

	public static KeystoreHelper getInstance()
	{
		if (instance == null)
		{
			synchronized (KeystoreHelper.class)
			{
				if (instance == null)
				{
					instance = new KeystoreHelper();
				}
			}
		}
		return instance;
	}

	// Returns Base64( IV[12] || ciphertext ), or the original value if blank.
	public String encrypt(String plaintext) throws KeystoreException
	{
		if (plaintext == null || plaintext.isEmpty())
			return plaintext;

		try
		{
			SecretKey key = generateOrGetKey();

			byte[] iv = new byte[GCM_IV_LENGTH];
			new SecureRandom().nextBytes(iv);

			Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

			byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

			// Pack: IV || ciphertext → Base64
			byte[] packed = new byte[GCM_IV_LENGTH + ciphertext.length];
			System.arraycopy(iv, 0, packed, 0, GCM_IV_LENGTH);
			System.arraycopy(ciphertext, 0, packed, GCM_IV_LENGTH, ciphertext.length);

			return Base64.encodeToString(packed, Base64.NO_WRAP);
		}
		catch (Exception e)
		{
			throw new KeystoreException("Encryption failed", e);
		}
	}

	// Decrypts a value produced by encrypt(). Legacy plaintext values are returned as-is.
	public String decrypt(String encoded) throws KeystoreException
	{
		if (encoded == null || encoded.isEmpty())
			return encoded;

		byte[] packed;
		try
		{
			packed = Base64.decode(encoded, Base64.NO_WRAP);
		}
		catch (IllegalArgumentException e)
		{
			// Not valid Base64 → plaintext legacy value, return as-is
			return encoded;
		}

		if (packed.length <= GCM_IV_LENGTH)
		{
			// Too short to be an encrypted blob → legacy plaintext
			return encoded;
		}

		try
		{
			SecretKey key = generateOrGetKey();

			byte[] iv = new byte[GCM_IV_LENGTH];
			byte[] ciphertext = new byte[packed.length - GCM_IV_LENGTH];
			System.arraycopy(packed, 0, iv, 0, GCM_IV_LENGTH);
			System.arraycopy(packed, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

			Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

			byte[] plainBytes = cipher.doFinal(ciphertext);
			return new String(plainBytes, "UTF-8");
		}
		catch (Exception e)
		{
			throw new KeystoreException("Decryption failed", e);
		}
	}

	private SecretKey generateOrGetKey() throws Exception
	{
		KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
		keyStore.load(null);

		if (keyStore.containsAlias(KEY_ALIAS))
		{
			return ((KeyStore.SecretKeyEntry)keyStore.getEntry(KEY_ALIAS, null)).getSecretKey();
		}

		KeyGenerator keyGen =
		    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER);
		keyGen.init(new KeyGenParameterSpec
		                .Builder(KEY_ALIAS,
		                         KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
		                .setKeySize(256)
		                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
		                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
		                .setRandomizedEncryptionRequired(false) // we supply our own IV
		                .build());

		return keyGen.generateKey();
	}

	public static final class KeystoreException extends Exception
	{
		public KeystoreException(String message, Throwable cause)
		{
			super(message, cause);
		}
	}
}
