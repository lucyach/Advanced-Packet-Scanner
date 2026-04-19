using System.Diagnostics;
using NetworkMonitor.UI;

namespace NetworkMonitor
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            // Kill any existing NetworkMonitor processes
            try
            {
                var existingProcesses = Process.GetProcessesByName("NetworkMonitor");
                foreach (var process in existingProcesses)
                {
                    if (process.Id != Environment.ProcessId) // Don't kill ourselves
                    {
                        process.Kill();
                        process.WaitForExit();
                    }
                }
                if (existingProcesses.Length > 1)
                {
                    Console.WriteLine($"Killed {existingProcesses.Length - 1} existing NetworkMonitor process(es)");
                    Thread.Sleep(1000); // Wait a moment for cleanup
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not kill existing processes: {ex.Message}");
            }

            // Configure the application for high DPI support
            ApplicationConfiguration.Initialize();
            
            // Display startup message in console
            Console.WriteLine("\n" + new string('=', 60));
            Console.WriteLine("📱 NETWORK MONITOR - POPUP APPLICATION");
            Console.WriteLine(new string('=', 60));
            Console.WriteLine("✅ Starting Windows Forms popup application...");
            Console.WriteLine("💡 A popup window will appear shortly");
            Console.WriteLine("🛑 Close the popup window to exit the application");
            Console.WriteLine(new string('=', 60) + "\n");

            // Create and run the main form
            Application.Run(new MainForm());
        }
    }
}