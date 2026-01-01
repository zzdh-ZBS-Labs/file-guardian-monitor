using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace FileGuardian
{
    class Program
    {
        // ===== CONFIGURATION =====
        private static string monitorPath = string.Empty; // User-provided at runtime
        private static readonly string backupPath = @"C:\Backup\Captured";
        private static readonly int debounceMs = 200;
        private static readonly int maxRetries = 5;
        private static readonly long maxFileSizeBytes = 1000 * 1024 * 1024; // 1GB
        // =========================

        // P/Invoke for hardlink creation
        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateHardLink(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);

        private static FileSystemWatcher watcher;
        private static readonly ConcurrentDictionary<string, DateTime> pendingFiles =
            new ConcurrentDictionary<string, DateTime>();
        private static readonly ConcurrentDictionary<string, byte> processingFiles =
            new ConcurrentDictionary<string, byte>();
        private static readonly CancellationTokenSource cts = new CancellationTokenSource();

        static async Task Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╔═══════════════════════════════════════════╗");
            Console.WriteLine("║     FILE GUARDIAN MONITOR v3.1            ║");
            Console.WriteLine("║   Malware Rapid-Deletion Prevention       ║");
            Console.WriteLine("╚═══════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();

            // Get monitor path from command line or user input
            monitorPath = GetMonitorPath(args);
            if (string.IsNullOrEmpty(monitorPath))
            {
                LogError("No valid monitor path provided. Exiting...");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            // Validate directories
            if (!Directory.Exists(monitorPath))
            {
                LogError($"Monitor directory does not exist: {monitorPath}");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            // Create backup directory structure
            try
            {
                Directory.CreateDirectory(backupPath);
                Directory.CreateDirectory(Path.Combine(backupPath, "_logs"));
                Directory.CreateDirectory(Path.Combine(backupPath, "_staging"));
                LogInfo($"Created backup directory: {backupPath}");
            }
            catch (Exception ex)
            {
                LogError($"Failed to create backup directory: {ex.Message}");
                return;
            }

            LogInfo($"Monitoring: {monitorPath}");
            LogInfo($"Backup to:  {backupPath}");
            LogInfo($"Method:     Hardlink + Stream Copy");
            Console.WriteLine();

            // Initialize FileSystemWatcher
            watcher = new FileSystemWatcher
            {
                Path = monitorPath,
                NotifyFilter = NotifyFilters.FileName
                             | NotifyFilters.LastWrite
                             | NotifyFilters.Size
                             | NotifyFilters.CreationTime,
                Filter = "*.*",
                IncludeSubdirectories = true,
                EnableRaisingEvents = true,
                InternalBufferSize = 64 * 1024
            };

            watcher.Created += OnFileChanged;
            watcher.Changed += OnFileChanged;
            watcher.Renamed += OnFileRenamed;
            watcher.Deleted += OnFileDeleted;
            watcher.Error += OnError;

            // Start debounce processor
            _ = Task.Run(() => ProcessPendingFiles(cts.Token));

            LogSuccess("File Guardian is active - capturing all files including deleted ones.");
            LogInfo("Press 'Q' to quit.");
            Console.WriteLine();

            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Q)
                {
                    LogInfo("Shutting down...");
                    cts.Cancel();
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                    await Task.Delay(1000);
                    break;
                }
            }
        }

        private static string GetMonitorPath(string[] args)
        {
            string path = string.Empty;

            // Check command line arguments first
            if (args.Length > 0)
            {
                path = args[0];
                LogInfo($"Using path from command line: {path}");
            }
            else
            {
                // Interactive input
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Enter the directory path to monitor:");
                Console.WriteLine("Examples:");
                Console.WriteLine("  C:\\Users\\YourUser\\AppData");
                Console.WriteLine("  C:\\Users\\YourUser\\Downloads");
                Console.WriteLine("  C:\\Temp");
                Console.ResetColor();
                Console.Write("\nPath: ");

                while (true)
                {
                    path = Console.ReadLine()?.Trim();

                    if (string.IsNullOrWhiteSpace(path))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Error: Path cannot be empty.");
                        Console.ResetColor();
                        Console.Write("Path: ");
                        continue;
                    }

                    // Remove surrounding quotes if present
                    path = path.Trim('"', '\'');

                    // Validate path format
                    if (!IsValidPath(path))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Error: Invalid path format: {path}");
                        Console.ResetColor();
                        Console.Write("Path: ");
                        continue;
                    }

                    // Check if directory exists
                    if (!Directory.Exists(path))
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"Warning: Directory does not exist: {path}");
                        Console.Write("Do you want to create it? (y/n): ");
                        Console.ResetColor();

                        var response = Console.ReadKey();
                        Console.WriteLine();

                        if (response.Key == ConsoleKey.Y)
                        {
                            try
                            {
                                Directory.CreateDirectory(path);
                                LogSuccess($"Created directory: {path}");
                                break;
                            }
                            catch (Exception ex)
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine($"Error: Failed to create directory: {ex.Message}");
                                Console.ResetColor();
                                Console.Write("Path: ");
                                continue;
                            }
                        }
                        else
                        {
                            Console.Write("Path: ");
                            continue;
                        }
                    }

                    break;
                }

                Console.WriteLine();
            }

            return path;
        }

        private static bool IsValidPath(string path)
        {
            try
            {
                // Check for invalid characters
                if (path.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
                    return false;

                // Try to get full path - will throw if invalid
                string fullPath = Path.GetFullPath(path);

                // Check if path is rooted (has drive letter or UNC path)
                if (!Path.IsPathRooted(path))
                    return false;

                // Additional check for drive letter existence
                string root = Path.GetPathRoot(fullPath);
                if (string.IsNullOrEmpty(root))
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            if (Directory.Exists(e.FullPath)) return;

            string eventType = e.ChangeType.ToString();
            LogEvent($"[{eventType}] {e.FullPath}");

            pendingFiles.AddOrUpdate(e.FullPath, DateTime.Now, (key, oldValue) => DateTime.Now);
        }

        private static void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (Directory.Exists(e.FullPath)) return;

            LogEvent($"[RENAMED] {e.OldFullPath} → {e.FullPath}");
            pendingFiles.AddOrUpdate(e.FullPath, DateTime.Now, (key, oldValue) => DateTime.Now);
        }

        private static void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            LogWarning($"[DELETED] {e.FullPath}");
            pendingFiles.TryRemove(e.FullPath, out _);

            string stagingFile = GetStagingPath(e.FullPath);
            if (File.Exists(stagingFile))
            {
                LogWarning($"[RECOVERY] Using staged copy: {Path.GetFileName(e.FullPath)}");
                _ = Task.Run(() => FinalizeStagedFile(stagingFile, e.FullPath));
            }
        }

        private static void OnError(object sender, ErrorEventArgs e)
        {
            LogError($"Watcher error: {e.GetException()?.Message}");
        }

        private static async Task ProcessPendingFiles(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(50, token);

                    var now = DateTime.Now;
                    foreach (var kvp in pendingFiles.ToArray())
                    {
                        if ((now - kvp.Value).TotalMilliseconds > debounceMs)
                        {
                            if (pendingFiles.TryRemove(kvp.Key, out _))
                            {
                                if (processingFiles.TryAdd(kvp.Key, 0))
                                {
                                    _ = Task.Run(() => CaptureFileAsync(kvp.Key, token));
                                }
                            }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    LogError($"Debounce error: {ex.Message}");
                }
            }
        }

        private static async Task CaptureFileAsync(string sourcePath, CancellationToken token)
        {
            try
            {
                int retries = 0;
                int delayMs = 50;

                while (retries < maxRetries)
                {
                    try
                    {
                        if (!File.Exists(sourcePath))
                        {
                            LogWarning($"File already deleted: {Path.GetFileName(sourcePath)}");
                            processingFiles.TryRemove(sourcePath, out _);
                            return;
                        }

                        var fileInfo = new FileInfo(sourcePath);

                        if (fileInfo.Length > maxFileSizeBytes)
                        {
                            LogWarning($"File too large ({fileInfo.Length / 1024 / 1024}MB): {Path.GetFileName(sourcePath)}");
                            processingFiles.TryRemove(sourcePath, out _);
                            return;
                        }

                        string relativePath = Path.GetRelativePath(monitorPath, sourcePath);
                        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
                        string destDir = Path.Combine(backupPath, Path.GetDirectoryName(relativePath) ?? "");
                        string filename = Path.GetFileNameWithoutExtension(sourcePath);
                        string extension = Path.GetExtension(sourcePath);
                        string destPath = Path.Combine(destDir, $"{filename}_{timestamp}{extension}");
                        string stagingPath = GetStagingPath(sourcePath);

                        Directory.CreateDirectory(destDir);
                        Directory.CreateDirectory(Path.GetDirectoryName(stagingPath));

                        if (TryCreateHardLink(sourcePath, stagingPath))
                        {
                            LogSuccess($"✓ Hardlinked: {Path.GetFileName(sourcePath)} (protected from deletion)");
                            await CopyWithHashAsync(stagingPath, destPath, sourcePath);
                            try { File.Delete(stagingPath); } catch { }
                            processingFiles.TryRemove(sourcePath, out _);
                            return;
                        }

                        await CopyWithLockedHandleAsync(sourcePath, stagingPath, destPath, fileInfo);
                        processingFiles.TryRemove(sourcePath, out _);
                        return;
                    }
                    catch (IOException ex) when (retries < maxRetries - 1)
                    {
                        retries++;
                        LogWarning($"Retry {retries}/{maxRetries}: {Path.GetFileName(sourcePath)} ({ex.Message.Split('\n')[0]})");
                        await Task.Delay(delayMs, token);
                        delayMs *= 2;
                    }
                    catch (UnauthorizedAccessException)
                    {
                        LogError($"Access denied: {Path.GetFileName(sourcePath)} - Run as Administrator");
                        processingFiles.TryRemove(sourcePath, out _);
                        return;
                    }
                }

                LogError($"Failed after {maxRetries} retries: {Path.GetFileName(sourcePath)}");
                processingFiles.TryRemove(sourcePath, out _);
            }
            catch (Exception ex)
            {
                LogError($"Capture error: {ex.Message}");
                processingFiles.TryRemove(sourcePath, out _);
            }
        }

        private static bool TryCreateHardLink(string source, string dest)
        {
            try
            {
                return CreateHardLink(dest, source, IntPtr.Zero);
            }
            catch
            {
                return false;
            }
        }

        private static async Task CopyWithLockedHandleAsync(string sourcePath, string stagingPath,
            string destPath, FileInfo sourceInfo)
        {
            using (var sourceStream = new FileStream(sourcePath, FileMode.Open,
                FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                using (var stagingStream = new FileStream(stagingPath, FileMode.Create,
                    FileAccess.Write, FileShare.None, 4096,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    await sourceStream.CopyToAsync(stagingStream, 81920);
                }

                sourceStream.Position = 0;
                string hash;
                using (var sha256 = SHA256.Create())
                {
                    byte[] hashBytes = await sha256.ComputeHashAsync(sourceStream);
                    hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }

                File.Copy(stagingPath, destPath, true);
                File.SetCreationTime(destPath, sourceInfo.CreationTime);
                File.SetLastWriteTime(destPath, sourceInfo.LastWriteTime);

                try { File.Delete(stagingPath); } catch { }

                await LogMetadataAsync(destPath, sourcePath, sourceInfo.Length, hash);
                LogSuccess($"✓ Captured: {Path.GetFileName(destPath)} ({sourceInfo.Length / 1024}KB, SHA256: {hash.Substring(0, 16)}...)");
            }
        }

        private static async Task CopyWithHashAsync(string sourcePath, string destPath, string originalPath)
        {
            try
            {
                var fileInfo = new FileInfo(originalPath);

                using (var sourceStream = new FileStream(sourcePath, FileMode.Open,
                    FileAccess.Read, FileShare.ReadWrite, 4096,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                using (var destStream = new FileStream(destPath, FileMode.Create,
                    FileAccess.Write, FileShare.None, 4096,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    await sourceStream.CopyToAsync(destStream, 81920);
                    sourceStream.Position = 0;

                    string hash;
                    using (var sha256 = SHA256.Create())
                    {
                        byte[] hashBytes = await sha256.ComputeHashAsync(sourceStream);
                        hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                    }

                    File.SetCreationTime(destPath, fileInfo.CreationTime);
                    File.SetLastWriteTime(destPath, fileInfo.LastWriteTime);

                    await LogMetadataAsync(destPath, originalPath, fileInfo.Length, hash);
                    LogSuccess($"✓ Finalized: {Path.GetFileName(destPath)} ({fileInfo.Length / 1024}KB, SHA256: {hash.Substring(0, 16)}...)");
                }
            }
            catch (Exception ex)
            {
                LogError($"Hash copy error: {ex.Message}");
            }
        }

        private static async Task FinalizeStagedFile(string stagingFile, string originalPath)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
                string relativePath = Path.GetRelativePath(monitorPath, originalPath);
                string destDir = Path.Combine(backupPath, Path.GetDirectoryName(relativePath) ?? "");
                string filename = Path.GetFileNameWithoutExtension(originalPath);
                string extension = Path.GetExtension(originalPath);
                string destPath = Path.Combine(destDir, $"{filename}_{timestamp}_RECOVERED{extension}");

                Directory.CreateDirectory(destDir);

                var fileInfo = new FileInfo(stagingFile);
                using (var sourceStream = new FileStream(stagingFile, FileMode.Open,
                    FileAccess.Read, FileShare.ReadWrite, 4096,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                using (var destStream = new FileStream(destPath, FileMode.Create,
                    FileAccess.Write, FileShare.None, 4096,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    await sourceStream.CopyToAsync(destStream, 81920);
                    sourceStream.Position = 0;

                    string hash;
                    using (var sha256 = SHA256.Create())
                    {
                        byte[] hashBytes = await sha256.ComputeHashAsync(sourceStream);
                        hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                    }

                    await LogMetadataAsync(destPath, originalPath, fileInfo.Length, hash);
                    LogSuccess($"✓ Recovered: {Path.GetFileName(destPath)} ({fileInfo.Length / 1024}KB)");
                }
            }
            catch (Exception ex)
            {
                LogError($"Recovery error: {ex.Message}");
            }
        }

        private static string GetStagingPath(string sourcePath)
        {
            string filename = Path.GetFileNameWithoutExtension(sourcePath);
            string extension = Path.GetExtension(sourcePath);
            return Path.Combine(backupPath, "_staging", $"{filename}_{Guid.NewGuid().ToString().Substring(0, 8)}{extension}");
        }

        private static async Task LogMetadataAsync(string destPath, string sourcePath, long size, string hash)
        {
            try
            {
                string logPath = Path.Combine(backupPath, "_logs", $"capture_{DateTime.Now:yyyyMMdd}.log");
                string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}|{sourcePath}|{destPath}|{size}|{hash}\n";
                await File.AppendAllTextAsync(logPath, logEntry);
            }
            catch { }
        }

        private static void LogInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {message}");
            Console.ResetColor();
        }

        private static void LogSuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {message}");
            Console.ResetColor();
        }

        private static void LogWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {message}");
            Console.ResetColor();
        }

        private static void LogError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] ERROR: {message}");
            Console.ResetColor();
        }

        private static void LogEvent(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {message}");
            Console.ResetColor();
        }
    }
}
