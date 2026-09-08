package com.dsh.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import java.util.concurrent.Executors

/**
 * 内置 SSH 隧道前台服务。
 *
 * 不需要 Termux，APK 自己通过 JSch 建立 SSH 本地端口转发，
 * 把服务器的 dsh web 端口映射到手机 127.0.0.1 的本地端口。
 */
class SshTunnelService : Service() {

    private val executor = Executors.newSingleThreadExecutor()
    private var currentSession: Session? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val config = SshConfig.fromIntent(intent)
                if (config != null) {
                    startForegroundWithNotification("正在连接 ${config.host} ...")
                    connect(config)
                } else {
                    SshTunnelState.connecting = false
                    SshTunnelState.connected = false
                    SshTunnelState.message = "连接失败：配置无效"
                    stopSelf()
                }
            }
            ACTION_DISCONNECT -> {
                disconnect()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun connect(config: SshConfig) {
        SshTunnelState.connected = false
        SshTunnelState.connecting = true
        SshTunnelState.message = "正在连接 ${config.host} ..."
        executor.execute {
            try {
                disconnectInternal()

                val jsch = JSch()
                applyAuthentication(jsch, config)
                val session = jsch.getSession(config.username, config.host, config.sshPort)
                applySessionAuth(session, config)
                // MVP 先接受任何主机密钥；后续可加入 known_hosts 校验
                session.setConfig("StrictHostKeyChecking", "no")
                session.setConfig("ServerAliveInterval", "30")
                session.setConfig("ServerAliveCountMax", "3")
                session.connect(15000)

                session.setPortForwardingL(
                    "127.0.0.1",
                    config.localPort,
                    "127.0.0.1",
                    config.dshPort
                )

                currentSession = session
                SshTunnelState.session = session
                SshTunnelState.connecting = false
                SshTunnelState.connected = true
                SshTunnelState.localPort = config.localPort
                SshTunnelState.message = "已连接：127.0.0.1:${config.localPort} -> 127.0.0.1:${config.dshPort}"
                updateNotification(SshTunnelState.message)
            } catch (e: Exception) {
                SshTunnelState.connecting = false
                SshTunnelState.connected = false
                SshTunnelState.message = "连接失败：${e.message ?: e.javaClass.simpleName}"
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun applyAuthentication(jsch: JSch, config: SshConfig) {
        if (!config.usePrivateKey) return
        val passphrase = config.password
            .takeIf { it.isNotEmpty() && SshPrivateKey.isEncrypted(config.privateKey) }
            ?.toByteArray(Charsets.UTF_8)
        jsch.addIdentity(
            "dsh-mobile",
            config.privateKey.toByteArray(Charsets.UTF_8),
            null,
            passphrase
        )
    }

    private fun applySessionAuth(session: Session, config: SshConfig) {
        if (config.usePrivateKey) {
            val detected = SshPrivateKey.detect(config.privateKey)
                ?: throw IllegalArgumentException("无法识别私钥格式")
            session.setConfig("PreferredAuthentications", "publickey")
            session.setConfig("PubkeyAcceptedAlgorithms", detected.pubkeyAcceptedAlgorithms)
            session.setConfig("PubkeyAcceptedKeyTypes", detected.pubkeyAcceptedAlgorithms)
        } else {
            session.setPassword(config.password)
            session.setConfig("PreferredAuthentications", "password,keyboard-interactive")
        }
    }

    private fun disconnect() {
        executor.execute {
            disconnectInternal()
            SshTunnelState.connecting = false
            SshTunnelState.connected = false
            SshTunnelState.session = null
            SshTunnelState.message = "已断开"
        }
    }

    private fun disconnectInternal() {
        try {
            currentSession?.disconnect()
        } catch (_: Exception) {
        }
        currentSession = null
    }

    override fun onDestroy() {
        disconnectInternal()
        SshTunnelState.connecting = false
        SshTunnelState.connected = false
        SshTunnelState.session = null
        SshTunnelState.message = "未连接"
        executor.shutdown()
        super.onDestroy()
    }

    private fun startForegroundWithNotification(text: String) {
        val notification = buildNotification(text)
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            notification,
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
        )
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle("dsh SSH 隧道")
            .setContentText(text)
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID,
            "dsh SSH 隧道",
            NotificationManager.IMPORTANCE_LOW
        )
        manager.createNotificationChannel(channel)
    }

    data class SshConfig(
        val host: String,
        val sshPort: Int,
        val username: String,
        val password: String,
        val dshPort: Int,
        val localPort: Int,
        val usePrivateKey: Boolean = false,
        val privateKey: String = ""
    ) {
        companion object {
            fun fromIntent(intent: Intent): SshConfig? {
                val host = intent.getStringExtra(EXTRA_HOST) ?: return null
                val username = intent.getStringExtra(EXTRA_USERNAME) ?: return null
                val password = intent.getStringExtra(EXTRA_PASSWORD) ?: ""
                val usePrivateKey = intent.getBooleanExtra(EXTRA_USE_PRIVATE_KEY, false)
                val privateKey = intent.getStringExtra(EXTRA_PRIVATE_KEY) ?: ""
                if (usePrivateKey) {
                    if (privateKey.isBlank() || SshPrivateKey.detect(privateKey) == null) return null
                } else if (password.isEmpty()) {
                    return null
                }
                return SshConfig(
                    host = host,
                    sshPort = intent.getIntExtra(EXTRA_SSH_PORT, 22),
                    username = username,
                    password = password,
                    dshPort = intent.getIntExtra(EXTRA_DSH_PORT, 3080),
                    localPort = intent.getIntExtra(EXTRA_LOCAL_PORT, 3080),
                    usePrivateKey = usePrivateKey,
                    privateKey = privateKey
                )
            }
        }
    }

    companion object {
        private const val CHANNEL_ID = "dsh_tunnel"
        private const val NOTIFICATION_ID = 1001
        private const val ACTION_CONNECT = "com.dsh.mobile.action.CONNECT"
        private const val ACTION_DISCONNECT = "com.dsh.mobile.action.DISCONNECT"
        private const val EXTRA_HOST = "host"
        private const val EXTRA_SSH_PORT = "ssh_port"
        private const val EXTRA_USERNAME = "username"
        private const val EXTRA_PASSWORD = "password"
        private const val EXTRA_USE_PRIVATE_KEY = "use_private_key"
        private const val EXTRA_PRIVATE_KEY = "private_key"
        private const val EXTRA_DSH_PORT = "dsh_port"
        private const val EXTRA_LOCAL_PORT = "local_port"

        fun start(context: Context, config: SshConfig) {
            val intent = Intent(context, SshTunnelService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_HOST, config.host)
                putExtra(EXTRA_SSH_PORT, config.sshPort)
                putExtra(EXTRA_USERNAME, config.username)
                putExtra(EXTRA_PASSWORD, config.password)
                putExtra(EXTRA_USE_PRIVATE_KEY, config.usePrivateKey)
                putExtra(EXTRA_PRIVATE_KEY, config.privateKey)
                putExtra(EXTRA_DSH_PORT, config.dshPort)
                putExtra(EXTRA_LOCAL_PORT, config.localPort)
            }
            androidx.core.content.ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, SshTunnelService::class.java).apply {
                action = ACTION_DISCONNECT
            }
            context.startService(intent)
        }
    }
}
