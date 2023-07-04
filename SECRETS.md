Secrets
=======

This document contains information about the secrets that this service uses.
The shell commands were writting on MacOS so you might need to alter the `base64` calls, the flags are different on Linux.

You may assume that the paragraphs with **How to generate this secret?** always produce base64 encoded output that is ready to be pasted in k8s.

crypto / key-import-decryption-key
---

**Type**

RSA private key in PEM format *without* the `----- BEGIN PRIVATE KEY -----` and corresponding end marker.

**Spring property**

`yolt.crypto.decryptionKey`

**Getting the secret from k8s**

```
$ kubectl get secret crypto -o json | \
  jq -r '.data["key-import-decryption-key"]' | \
  base64 -D | base64 -D | \
  openssl rsa -inform der -noout -text
```

**How to check if the currently configured secret is correct?**

Check that it is a 2048 bit key.

**How to generate this secret?**

This secret is part of a keypair, when you change this secret, you *must* also change the corresponding secret that is used by the `providers` / `providers` project at the same time.
To do this, follow the instructions in the `SECRETS.md` file in the `providers` / `providers` project.

`$ priv=$(2>/dev/null openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform der | base64 | base64)`

`${priv}` now contains the secret.
