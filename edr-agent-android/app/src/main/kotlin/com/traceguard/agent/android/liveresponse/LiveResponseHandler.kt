package com.traceguard.agent.android.liveresponse

import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import com.traceguard.agent.events.LiveCommand
import com.traceguard.agent.events.LiveResult
import java.io.File

private val BLOCKED = Regex("rm\\s+-rf|mkfs|dd\\s+if=|shutdown|reboot|format\\s+[cC]:")

class LiveResponseHandler(private val context: Context) {

    suspend fun handle(cmd: LiveCommand): LiveResult {
        if (BLOCKED.containsMatchIn(cmd.action + " " + cmd.args.joinToString(" "))) {
            return error(cmd, "blocked: dangerous command pattern")
        }
        return when (cmd.action) {
            "ps"      -> handlePs(cmd)
            "ls"      -> handleLs(cmd)
            "cat"     -> handleCat(cmd)
            "id"      -> handleId(cmd)
            "getprop" -> handleGetprop(cmd)
            "pm"      -> handlePm(cmd)
            "dumpsys" -> handleDumpsys(cmd)
            "kill"    -> handleKill(cmd)
            "netstat" -> handleNetstat(cmd)
            "exec"    -> handleExec(cmd)
            else      -> error(cmd, "unknown action: ${cmd.action}")
        }
    }

    private fun handlePs(cmd: LiveCommand): LiveResult {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val procs = am.runningAppProcesses ?: emptyList()
        val out = procs.joinToString("\n") { p ->
            "${p.pid}\t${importanceLabel(p.importance)}\t${p.processName}"
        }
        return ok(cmd, "PID\tSTATUS\tNAME\n$out")
    }

    private fun handleLs(cmd: LiveCommand): LiveResult {
        val path = cmd.args.firstOrNull() ?: return error(cmd, "ls: path required")
        val dir  = File(path)
        if (!dir.exists()) return error(cmd, "ls: no such file or directory: $path")
        val listing = if (dir.isDirectory) {
            dir.listFiles()?.joinToString("\n") { f ->
                val type = if (f.isDirectory) "d" else "-"
                "$type  ${f.length()}\t${f.name}"
            } ?: ""
        } else {
            "${dir.length()}\t${dir.name}"
        }
        return ok(cmd, listing)
    }

    private fun handleCat(cmd: LiveCommand): LiveResult {
        val path = cmd.args.firstOrNull() ?: return error(cmd, "cat: path required")
        val file = File(path)
        if (!file.exists() || !file.isFile) return error(cmd, "cat: $path: no such file")
        if (file.length() > 1_048_576) return error(cmd, "cat: file too large (>1MB)")
        return ok(cmd, file.readText())
    }

    private fun handleId(cmd: LiveCommand): LiveResult =
        ok(cmd, "uid=${Process.myUid()} pid=${Process.myPid()}")

    private fun handleGetprop(cmd: LiveCommand): LiveResult {
        val key = cmd.args.firstOrNull()
        val out = if (key != null) {
            runShell("getprop $key")
        } else {
            "brand=${Build.BRAND}\nmodel=${Build.MODEL}\n" +
            "release=${Build.VERSION.RELEASE}\napi=${Build.VERSION.SDK_INT}\n" +
            "fingerprint=${Build.FINGERPRINT}"
        }
        return ok(cmd, out)
    }

    private fun handlePm(cmd: LiveCommand): LiveResult {
        val sub = cmd.args.firstOrNull()
        return when (sub) {
            "list" -> {
                val pm = context.packageManager
                @Suppress("DEPRECATION")
                val pkgs = pm.getInstalledPackages(0)
                    .joinToString("\n") { "package:${it.packageName}" }
                ok(cmd, pkgs)
            }
            else -> error(cmd, "pm: unsupported subcommand: $sub")
        }
    }

    private fun handleDumpsys(cmd: LiveCommand): LiveResult {
        val service = cmd.args.firstOrNull() ?: "battery"
        val allowed = setOf("battery", "wifi", "connectivity", "cpuinfo", "meminfo")
        if (service !in allowed) return error(cmd, "dumpsys: service not in allowlist")
        return ok(cmd, runShell("dumpsys $service"))
    }

    private fun handleKill(cmd: LiveCommand): LiveResult {
        val pid = cmd.args.firstOrNull()?.toIntOrNull()
            ?: return error(cmd, "kill: pid required")
        return try {
            Process.killProcess(pid)
            ok(cmd, "killed $pid")
        } catch (e: Exception) {
            error(cmd, "kill failed: ${e.message}")
        }
    }

    private fun handleNetstat(cmd: LiveCommand): LiveResult {
        val tcp  = runCatching { File("/proc/net/tcp").readText() }.getOrDefault("")
        val tcp6 = runCatching { File("/proc/net/tcp6").readText() }.getOrDefault("")
        return ok(cmd, "=== /proc/net/tcp ===\n$tcp\n=== /proc/net/tcp6 ===\n$tcp6")
    }

    private fun handleExec(cmd: LiveCommand): LiveResult {
        if (cmd.args.isEmpty()) return error(cmd, "exec: command required")
        val command = cmd.args.joinToString(" ")
        // secondary blocklist check on the exec args
        if (BLOCKED.containsMatchIn(command)) return error(cmd, "blocked: dangerous command")
        return ok(cmd, runShell(command))
    }

    private fun runShell(command: String): String = try {
        val proc   = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))
        val stdout = proc.inputStream.bufferedReader().readText().take(1_048_576)
        proc.waitFor()
        stdout
    } catch (e: Exception) {
        "error: ${e.message}"
    }

    private fun importanceLabel(importance: Int): String = when (importance) {
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND         -> "FOREGROUND"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE -> "FG_SERVICE"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE            -> "VISIBLE"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE            -> "SERVICE"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_CACHED             -> "CACHED"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_GONE               -> "GONE"
        else                                                                 -> "UNKNOWN($importance)"
    }

    private fun ok(cmd: LiveCommand, stdout: String) = LiveResult(
        commandId = cmd.commandId,
        agentId   = "",
        status    = "completed",
        exitCode  = 0,
        stdout    = stdout,
    )

    private fun error(cmd: LiveCommand, msg: String) = LiveResult(
        commandId = cmd.commandId,
        agentId   = "",
        status    = "error",
        exitCode  = 1,
        error     = msg,
    )
}
