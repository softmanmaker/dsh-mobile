package com.dsh.mobile

import android.util.Base64
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * 根据私钥 PEM 开头（及 OpenSSH / PKCS#8 头部信息）识别公钥算法，
 * 供 JSch 限制 [PubkeyAcceptedAlgorithms]。
 */
object SshPrivateKey {

    data class DetectedKey(
        val algorithm: String,
        val pubkeyAcceptedAlgorithms: String
    )

    fun isEncrypted(privateKey: String): Boolean {
        val pem = privateKey.replace("\r\n", "\n")
        if (pem.contains("BEGIN ENCRYPTED PRIVATE KEY") || pem.contains("Proc-Type: 4,ENCRYPTED")) {
            return true
        }
        val header = pem.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.startsWith("-----BEGIN ") && it.endsWith("-----") }
            ?: return false
        if (!header.contains("OPENSSH PRIVATE KEY")) return false
        val body = decodePemBody(pem) ?: return false
        val magic = "openssh-key-v1\u0000".toByteArray(StandardCharsets.US_ASCII)
        if (body.size < magic.size || !body.copyOfRange(0, magic.size).contentEquals(magic)) {
            return false
        }
        return try {
            val buf = ByteBuffer.wrap(body, magic.size, body.size - magic.size)
            val cipher = String(readOpenSshString(buf), StandardCharsets.US_ASCII)
            cipher.isNotEmpty() && cipher != "none"
        } catch (_: Exception) {
            false
        }
    }

    fun detect(privateKey: String): DetectedKey? {
        val pem = privateKey.replace("\r\n", "\n").trim()
        val header = pem.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.startsWith("-----BEGIN ") && it.endsWith("-----") }
            ?: return null

        return when {
            header.contains("RSA PRIVATE KEY") ->
                DetectedKey("ssh-rsa", RSA_ALGOS)
            header.contains("DSA PRIVATE KEY") ->
                DetectedKey("ssh-dss", "ssh-dss")
            header.contains("EC PRIVATE KEY") ->
                DetectedKey("ecdsa", ECDSA_ALGOS)
            header.contains("OPENSSH PRIVATE KEY") ->
                detectOpenSsh(pem)
            header.contains("ENCRYPTED PRIVATE KEY") || header.contains("PRIVATE KEY") ->
                detectPkcs8(pem) ?: DetectedKey("pkcs8", DEFAULT_ALGOS)
            else -> null
        }
    }

    private fun detectOpenSsh(pem: String): DetectedKey {
        val body = decodePemBody(pem) ?: return DetectedKey("openssh", DEFAULT_ALGOS)
        val magic = "openssh-key-v1\u0000".toByteArray(StandardCharsets.US_ASCII)
        if (body.size < magic.size || !body.copyOfRange(0, magic.size).contentEquals(magic)) {
            return DetectedKey("openssh", DEFAULT_ALGOS)
        }
        val buf = ByteBuffer.wrap(body, magic.size, body.size - magic.size)
        return try {
            readOpenSshString(buf) // ciphername
            readOpenSshString(buf) // kdfname
            readOpenSshString(buf) // kdfoptions
            if (buf.remaining() < 4) return DetectedKey("openssh", DEFAULT_ALGOS)
            val nkeys = buf.int
            if (nkeys < 1) return DetectedKey("openssh", DEFAULT_ALGOS)
            val publicKey = readOpenSshString(buf)
            val pubBuf = ByteBuffer.wrap(publicKey)
            val keyType = String(readOpenSshString(pubBuf), StandardCharsets.US_ASCII)
            algorithmsForOpenSshType(keyType)
        } catch (_: Exception) {
            DetectedKey("openssh", DEFAULT_ALGOS)
        }
    }

    private fun algorithmsForOpenSshType(keyType: String): DetectedKey {
        val algos = when (keyType) {
            "ssh-ed25519", "sk-ssh-ed25519@openssh.com" -> "ssh-ed25519"
            "ecdsa-sha2-nistp256", "sk-ecdsa-sha2-nistp256@openssh.com" -> "ecdsa-sha2-nistp256"
            "ecdsa-sha2-nistp384" -> "ecdsa-sha2-nistp384"
            "ecdsa-sha2-nistp521" -> "ecdsa-sha2-nistp521"
            "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512" -> RSA_ALGOS
            "ssh-dss" -> "ssh-dss"
            else -> DEFAULT_ALGOS
        }
        return DetectedKey(keyType, algos)
    }

    private fun detectPkcs8(pem: String): DetectedKey? {
        val der = decodePemBody(pem) ?: return null
        return when {
            containsOid(der, OID_RSA) -> DetectedKey("ssh-rsa", RSA_ALGOS)
            containsOid(der, OID_EC) -> DetectedKey("ecdsa", ECDSA_ALGOS)
            containsOid(der, OID_ED25519) -> DetectedKey("ssh-ed25519", "ssh-ed25519")
            containsOid(der, OID_DSA) -> DetectedKey("ssh-dss", "ssh-dss")
            else -> null
        }
    }

    private fun decodePemBody(pem: String): ByteArray? {
        val body = pem.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("-----") && ':' !in it }
            .joinToString("")
        if (body.isEmpty()) return null
        return try {
            Base64.decode(body, Base64.DEFAULT)
        } catch (_: Exception) {
            null
        }
    }

    private fun readOpenSshString(buf: ByteBuffer): ByteArray {
        if (buf.remaining() < 4) throw IllegalArgumentException("truncated")
        val length = buf.int
        if (length < 0 || length > buf.remaining()) throw IllegalArgumentException("invalid length")
        val bytes = ByteArray(length)
        buf.get(bytes)
        return bytes
    }

    private fun containsOid(der: ByteArray, oidBody: ByteArray): Boolean {
        val needle = byteArrayOf(0x06, oidBody.size.toByte()) + oidBody
        if (der.size < needle.size) return false
        outer@ for (i in 0..der.size - needle.size) {
            for (j in needle.indices) {
                if (der[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    private const val RSA_ALGOS = "rsa-sha2-512,rsa-sha2-256,ssh-rsa"
    private const val ECDSA_ALGOS = "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521"
    private const val DEFAULT_ALGOS =
        "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa"

    // 1.2.840.113549.1.1.1
    private val OID_RSA = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x01, 0x01)
    // 1.2.840.10045.2.1
    private val OID_EC = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01)
    // 1.3.101.112
    private val OID_ED25519 = byteArrayOf(0x2b, 0x65, 0x70)
    // 1.2.840.10040.4.1
    private val OID_DSA = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x38, 0x04, 0x01)
}
