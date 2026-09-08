package com.dsh.mobile

import android.Manifest
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.dsh.mobile.SshTunnelService.SshConfig
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.textfield.TextInputLayout

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var hostEditText: EditText
    private lateinit var sshPortEditText: EditText
    private lateinit var usernameEditText: EditText
    private lateinit var passwordEditText: EditText
    private lateinit var passwordLayout: TextInputLayout
    private lateinit var privateKeyModeCheckBox: MaterialCheckBox
    private lateinit var privateKeyLayout: TextInputLayout
    private lateinit var privateKeyEditText: EditText
    private lateinit var dshPortEditText: EditText
    private lateinit var localPortEditText: EditText
    private lateinit var connectButton: MaterialButton
    private lateinit var statusTextView: TextView
    private lateinit var statusDot: View
    private lateinit var configScroll: ScrollView

    private val handler = Handler(Looper.getMainLooper())
    private var loadedUrl: String? = null

    private val statusRunnable = object : Runnable {
        override fun run() {
            updateStatus()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        webView = findViewById(R.id.webView)
        hostEditText = findViewById(R.id.hostEditText)
        sshPortEditText = findViewById(R.id.sshPortEditText)
        usernameEditText = findViewById(R.id.usernameEditText)
        passwordEditText = findViewById(R.id.passwordEditText)
        passwordLayout = findViewById(R.id.passwordLayout)
        privateKeyModeCheckBox = findViewById(R.id.privateKeyModeCheckBox)
        privateKeyLayout = findViewById(R.id.privateKeyLayout)
        privateKeyEditText = findViewById(R.id.privateKeyEditText)
        dshPortEditText = findViewById(R.id.dshPortEditText)
        localPortEditText = findViewById(R.id.localPortEditText)
        connectButton = findViewById(R.id.connectButton)
        statusTextView = findViewById(R.id.statusTextView)
        statusDot = findViewById(R.id.statusDot)
        configScroll = findViewById(R.id.configScroll)

        setupWebView()
        requestNotificationPermissionIfNeeded()

        val prefs = getSharedPreferences("dsh_mobile", MODE_PRIVATE)
        hostEditText.setText(prefs.getString("host", ""))
        sshPortEditText.setText(prefs.getString("ssh_port", "22"))
        usernameEditText.setText(prefs.getString("username", ""))
        dshPortEditText.setText(prefs.getString("dsh_port", "3080"))
        localPortEditText.setText(prefs.getString("local_port", "3080"))
        passwordEditText.setText(prefs.getString("password", ""))
        privateKeyEditText.setText(prefs.getString("private_key", ""))
        privateKeyModeCheckBox.isChecked = prefs.getBoolean("use_private_key", false)
        privateKeyModeCheckBox.setOnCheckedChangeListener { _, _ -> updateAuthModeUi() }
        updateAuthModeUi()

        connectButton.setOnClickListener {
            if (SshTunnelState.connected) {
                SshTunnelState.connecting = false
                SshTunnelService.stop(this)
                connectButton.text = getString(R.string.connect)
            } else {
                val config = readConfig()
                if (config == null) {
                    Toast.makeText(this, configErrorMessage(), Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                saveConfig(config)
                SshTunnelState.connecting = true
                SshTunnelState.connected = false
                SshTunnelState.message = getString(R.string.connecting)
                SshTunnelService.start(this, config)
                connectButton.text = getString(R.string.disconnect)
                updateStatus()
            }
        }

        handler.post(statusRunnable)
    }

    override fun onDestroy() {
        handler.removeCallbacks(statusRunnable)
        super.onDestroy()
    }

    private fun configErrorMessage(): Int {
        val hostEmpty = hostEditText.text.toString().trim().isEmpty()
        val usernameEmpty = usernameEditText.text.toString().trim().isEmpty()
        val keyMode = privateKeyModeCheckBox.isChecked
        val keyBlank = privateKeyEditText.text.toString().isBlank()
        return when {
            hostEmpty || usernameEmpty -> if (keyMode) R.string.config_invalid_key else R.string.config_invalid
            keyMode && keyBlank -> R.string.config_invalid_key
            keyMode -> R.string.config_invalid_key_format
            else -> R.string.config_invalid
        }
    }

    private fun updateAuthModeUi() {
        val keyMode = privateKeyModeCheckBox.isChecked
        privateKeyLayout.isEnabled = keyMode
        privateKeyEditText.isEnabled = keyMode
        passwordLayout.hint = getString(
            if (keyMode) R.string.hint_private_key_passphrase else R.string.hint_password
        )
    }

    private fun readConfig(): SshConfig? {
        val host = hostEditText.text.toString().trim()
        val username = usernameEditText.text.toString().trim()
        val password = passwordEditText.text.toString()
        val usePrivateKey = privateKeyModeCheckBox.isChecked
        val privateKey = privateKeyEditText.text.toString().trim()
        val sshPort = sshPortEditText.text.toString().toIntOrNull() ?: 22
        val dshPort = dshPortEditText.text.toString().toIntOrNull() ?: 3080
        val localPort = localPortEditText.text.toString().toIntOrNull() ?: 3080

        if (host.isEmpty() || username.isEmpty()) {
            return null
        }
        if (usePrivateKey) {
            if (privateKey.isEmpty() || SshPrivateKey.detect(privateKey) == null) {
                return null
            }
        } else if (password.isEmpty()) {
            return null
        }
        return SshConfig(host, sshPort, username, password, dshPort, localPort, usePrivateKey, privateKey)
    }

    private fun saveConfig(config: SshConfig) {
        getSharedPreferences("dsh_mobile", MODE_PRIVATE).edit()
            .putString("host", config.host)
            .putString("ssh_port", config.sshPort.toString())
            .putString("username", config.username)
            .putString("password", config.password)
            .putBoolean("use_private_key", config.usePrivateKey)
            .putString("private_key", config.privateKey)
            .putString("dsh_port", config.dshPort.toString())
            .putString("local_port", config.localPort.toString())
            .apply()
    }

    private fun updateStatus() {
        statusTextView.text = SshTunnelState.message
        configScroll.visibility = if (SshTunnelState.connected) View.GONE else View.VISIBLE

        when {
            SshTunnelState.connected -> {
                connectButton.text = getString(R.string.disconnect)
                setStatusColor(R.color.status_connected)
                val url = "http://127.0.0.1:${SshTunnelState.localPort}"
                if (loadedUrl != url) {
                    loadedUrl = url
                    webView.loadUrl(url)
                }
            }
            SshTunnelState.connecting -> {
                connectButton.text = getString(R.string.disconnect)
                setStatusColor(R.color.status_connecting)
            }
            SshTunnelState.message.startsWith("连接失败") -> {
                connectButton.text = getString(R.string.connect)
                setStatusColor(R.color.status_error)
            }
            else -> {
                connectButton.text = getString(R.string.connect)
                setStatusColor(R.color.status_idle)
            }
        }
    }

    private fun setStatusColor(colorRes: Int) {
        val color = ContextCompat.getColor(this, colorRes)
        statusDot.backgroundTintList = ColorStateList.valueOf(color)
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33) {
            val permission = Manifest.permission.POST_NOTIFICATIONS
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(permission), 100)
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            loadWithOverviewMode = true
            useWideViewPort = true
            builtInZoomControls = true
            displayZoomControls = false
            mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
        }
        webView.webViewClient = WebViewClient()
        webView.webChromeClient = WebChromeClient()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }
}
