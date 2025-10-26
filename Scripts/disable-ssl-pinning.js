/**
 * This Frida script disables SSL pinning and verification on any target macOS process.
 * Updated for Frida 17+ (2025)
 * Original source:
 * https://gist.github.com/azenla/37f941de24c5dfe46f3b8e93d94ce909
 * Used for: https://github.com/trungnghiatn/Downgrade-MAS-Applications
 */

const SecurityModule = Process.getModuleByName('Security');
const libboringsslModule = Process.getModuleByName('libboringssl.dylib');

// === Exported handles ===
const SecTrustEvaluate_handle = SecurityModule.getExportByName('SecTrustEvaluate');
const SecTrustEvaluateWithError_handle = SecurityModule.getExportByName('SecTrustEvaluateWithError');
const SSL_CTX_set_custom_verify_handle = libboringsslModule.getExportByName('SSL_CTX_set_custom_verify');
const SSL_get_psk_identity_handle = libboringsslModule.getExportByName('SSL_get_psk_identity');
const boringssl_context_set_verify_mode_handle = libboringsslModule.getExportByName('boringssl_context_set_verify_mode');

// === Hook SecTrustEvaluateWithError() ===
if (SecTrustEvaluateWithError_handle) {
  const SecTrustEvaluateWithError = new NativeFunction(
      SecTrustEvaluateWithError_handle, 'int', ['pointer', 'pointer']);

  Interceptor.replace(
      SecTrustEvaluateWithError_handle,
      new NativeCallback(function (trust, error) {
        console.log('[*] Called SecTrustEvaluateWithError()');
        SecTrustEvaluateWithError(trust, NULL);
        ptr(error).writeU8(0); // ✅ updated for Frida 17
        return 1; // means trusted
      }, 'int', ['pointer', 'pointer'])
  );
  console.log('[+] SecTrustEvaluateWithError() hook installed.');
}

// === Hook SecTrustEvaluate() ===
if (SecTrustEvaluate_handle) {
  const SecTrustEvaluate = new NativeFunction(
      SecTrustEvaluate_handle, 'int', ['pointer', 'pointer']);

  Interceptor.replace(
      SecTrustEvaluate_handle,
      new NativeCallback(function (trust, result) {
        console.log('[*] Called SecTrustEvaluate()');
        SecTrustEvaluate(trust, result);
        ptr(result).writeU8(1); // ✅ trusted
        return 0; // noErr
      }, 'int', ['pointer', 'pointer'])
  );
  console.log('[+] SecTrustEvaluate() hook installed.');
}

// === Hook SSL_CTX_set_custom_verify() ===
if (SSL_CTX_set_custom_verify_handle) {
  const SSL_CTX_set_custom_verify = new NativeFunction(
      SSL_CTX_set_custom_verify_handle, 'void', ['pointer', 'int', 'pointer']);

  const replaced_callback = new NativeCallback(function (ssl, out) {
    console.log('[*] Called custom SSL verifier');
    return 0; // accepted
  }, 'int', ['pointer', 'pointer']);

  Interceptor.replace(
      SSL_CTX_set_custom_verify_handle,
      new NativeCallback(function (ctx, mode, callback) {
        console.log('[*] Called SSL_CTX_set_custom_verify()');
        SSL_CTX_set_custom_verify(ctx, 0, replaced_callback);
      }, 'void', ['pointer', 'int', 'pointer'])
  );
  console.log('[+] SSL_CTX_set_custom_verify() hook installed.');
}

// === Hook SSL_get_psk_identity() ===
if (SSL_get_psk_identity_handle) {
  Interceptor.replace(
      SSL_get_psk_identity_handle,
      new NativeCallback(function (ssl) {
        console.log('[*] Called SSL_get_psk_identity_handle()');
        return Memory.allocUtf8String('notarealPSKidentity'); // ✅ fixed return type
      }, 'pointer', ['pointer'])
  );
  console.log('[+] SSL_get_psk_identity() hook installed.');
}

// === Hook boringssl_context_set_verify_mode() ===
if (boringssl_context_set_verify_mode_handle) {
  const boringssl_context_set_verify_mode = new NativeFunction(
      boringssl_context_set_verify_mode_handle, 'int', ['pointer', 'pointer']);

  Interceptor.replace(
      boringssl_context_set_verify_mode_handle,
      new NativeCallback(function (a, b) {
        console.log('[*] Called boringssl_context_set_verify_mode()');
        return 0;
      }, 'int', ['pointer', 'pointer'])
  );
  console.log('[+] boringssl_context_set_verify_mode() hook installed.');
}

console.log('✅ SSL pinning bypass hooks loaded successfully for Frida 17+.');
