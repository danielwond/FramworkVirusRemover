using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FramworkVirusRemover
{
    public partial class Form1 : Form
    {
        bool virusExists = false;

        public Form1()
        {
            InitializeComponent();
            FormBorderStyle = FormBorderStyle.FixedToolWindow;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            tTxtBox.Text = "";

            if (!IsProgramElevated())
            {
                MessageBox.Show("Please run as administrator", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly, false);
                Application.Exit();
            }
            try
            {
                foreach (var drive in GetNumberOfDrives())
                {
                    string folderPath = $"{drive}System_Volume_Information";
                    if (Directory.Exists(folderPath))
                    {
                        virusExists = true;

                        SetFolderPermissions(folderPath);
                        Directory.Delete(folderPath, true);
                        tTxtBox.Text = tTxtBox.Text + "\n" + $"Malicious Folder Existed in {drive}, But now deleted!";
                        return;
                    }
                    else
                    {
                        tTxtBox.Text = tTxtBox.Text + "\n" + $"Malicious Folder does not exist in {drive}";
                    }
                }
                DeleteRksuTemp();
                DeleteInfectedRegistry();

                LogFile();
                if (virusExists)
                {
                    MessageBox.Show($"All Done, \n On Desktop you will find the log", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                MessageBox.Show($"Virus does not exist", "Information", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);

                Application.Exit();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
        static void SetFolderPermissions(string folderPath)
        {
            DirectoryInfo directoryInfo = new DirectoryInfo(folderPath);
            DirectorySecurity directorySecurity = directoryInfo.GetAccessControl();

            AuthorizationRuleCollection rules = directorySecurity.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                directorySecurity.RemoveAccessRule(rule);
            }

            directorySecurity.AddAccessRule(new FileSystemAccessRule("Everyone",
                FileSystemRights.FullControl,
                InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            directoryInfo.SetAccessControl(directorySecurity);
        }
        static List<string> GetNumberOfDrives()
        {
            DriveInfo[] drives = DriveInfo.GetDrives();
            var driveLetters = drives.Where(x => x.DriveType == DriveType.Fixed).Select(x => x.Name).ToList();
            return driveLetters;
        }
        static bool IsProgramElevated()
        {
            using (Process process = Process.GetCurrentProcess())
            {
                return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        private void DeleteRksuTemp()
        {
            string tempPath = Path.GetTempPath();
            string[] folders = Directory.GetDirectories(tempPath, "rlgms*");

            if (folders.Any())
            {
                foreach (string folder in folders)
                {
                    if (Directory.Exists(folder))
                    {
                        virusExists = true;
                        Directory.Delete(folder, true);
                        tTxtBox.Text = tTxtBox.Text + "\n" + $"Malicious Folder {folder} in temp has been deleted!";
                    }
                }
            }
            tTxtBox.Text = tTxtBox.Text + "\n" + $"Malicious Folder does not exist in temp";
        }
        private void DeleteInfectedRegistry()
        {
            try
            {
                using (RegistryKey baseKey = Registry.CurrentUser.OpenSubKey("Software", true))
                {
                    if (baseKey.GetSubKeyNames().Contains("bt"))
                    {
                        virusExists = true;

                        baseKey.DeleteSubKeyTree("bt");
                        tTxtBox.Text = tTxtBox.Text + "\n" + $"Infected Registry Removed";
                    }
                    else
                    {
                        tTxtBox.Text = tTxtBox.Text + "\n" + $"No Infected Registry Found";
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
        private void LogFile()
        {
            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string logsDirectory = Path.Combine(desktopPath, "MyLogs");
            string fileName = "logremoved.txt";
            string filePath = Path.Combine(logsDirectory, fileName);

            try
            {
                // Create the logs directory if it doesn't exist
                if (!Directory.Exists(logsDirectory))
                {
                    Directory.CreateDirectory(logsDirectory);
                }

                //// Check if the file already exists
                //if (File.Exists(filePath))
                //{
                //    // Increment the sequence number until we find a filename that doesn't exist
                //    int sequence = 1;
                //    do
                //    {
                //        fileName = $"logremoved ({sequence}).txt";
                //        filePath = Path.Combine(logsDirectory, fileName);
                //        sequence++;
                //    } while (File.Exists(filePath));
                //}

                // Write the text to the file
                if (File.Exists(filePath))
                {
                    File.AppendAllLines(filePath, new List<string>() { "\n", DateTime.Now.ToString("dd/MM/yyyy hh:mm:ss") + tTxtBox.Text });
                }
                else
                {
                    File.AppendAllLines(filePath, new List<string>() { DateTime.Now.ToString("dd/MM/yyyy hh:mm:ss") + tTxtBox.Text });
                }
                Console.WriteLine($"Log file '{fileName}' created successfully at '{filePath}'.");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void btnClose_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }
    }
}
