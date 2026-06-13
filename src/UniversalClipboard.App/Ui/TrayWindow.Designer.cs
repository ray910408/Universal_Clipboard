using System.Drawing;
using System.Windows.Forms;

namespace UniversalClipboard.App.Ui;

public sealed partial class TrayWindow
{
    private NotifyIcon notifyIcon = null!;
    private Label serviceStatusLabel = null!;
    private Label serviceStatusValue = null!;
    private Label urlLabel = null!;
    private Label urlValue = null!;
    private Label firewallLabel = null!;
    private Label firewallValue = null!;
    private Label networkProfileLabel = null!;
    private Label networkProfileValue = null!;
    private Label portListeningLabel = null!;
    private Label portListeningValue = null!;
    private Label firewallSetupLabel = null!;
    private Label firewallSetupValue = null!;
    private Label warningLabel = null!;
    private Label retryLabel = null!;
    private Label retryValue = null!;
    private Label durationLabel = null!;
    private ComboBox durationComboBox = null!;
    private Label interfaceLabel = null!;
    private ComboBox interfaceComboBox = null!;
    private Label pairingUrlLabel = null!;
    private Label pairingUrlValue = null!;
    private PictureBox qrPictureBox = null!;
    private Label browserListLabel = null!;
    private ListBox browserListBox = null!;
    private ListBox sharedListBox = null!;
    private ListBox pendingListBox = null!;
    private Button startButton = null!;
    private Button stopButton = null!;
    private Button pairButton = null!;
    private Button revokeButton = null!;
    private Button revokeAllButton = null!;
    private Button withdrawButton = null!;
    private Button allowButton = null!;
    private Button discardButton = null!;
    private Button exitButton = null!;

    private void InitializeComponent()
    {
        notifyIcon = new NotifyIcon();
        serviceStatusLabel = new Label();
        serviceStatusValue = new Label();
        urlLabel = new Label();
        urlValue = new Label();
        firewallLabel = new Label();
        firewallValue = new Label();
        networkProfileLabel = new Label();
        networkProfileValue = new Label();
        portListeningLabel = new Label();
        portListeningValue = new Label();
        firewallSetupLabel = new Label();
        firewallSetupValue = new Label();
        warningLabel = new Label();
        retryLabel = new Label();
        retryValue = new Label();
        durationLabel = new Label();
        durationComboBox = new ComboBox();
        interfaceLabel = new Label();
        interfaceComboBox = new ComboBox();
        pairingUrlLabel = new Label();
        pairingUrlValue = new Label();
        qrPictureBox = new PictureBox();
        browserListLabel = new Label();
        browserListBox = new ListBox();
        sharedListBox = new ListBox();
        pendingListBox = new ListBox();
        startButton = new Button();
        stopButton = new Button();
        pairButton = new Button();
        revokeButton = new Button();
        revokeAllButton = new Button();
        withdrawButton = new Button();
        allowButton = new Button();
        discardButton = new Button();
        exitButton = new Button();
        SuspendLayout();

        notifyIcon.Text = "Universal Clipboard";
        notifyIcon.Visible = true;
        notifyIcon.Icon = SystemIcons.Application;

        serviceStatusLabel.Text = "Service";
        serviceStatusLabel.Location = new Point(12, 15);
        serviceStatusLabel.AutoSize = true;
        serviceStatusValue.Location = new Point(110, 15);
        serviceStatusValue.Size = new Size(450, 20);

        urlLabel.Text = "URL";
        urlLabel.Location = new Point(12, 42);
        urlLabel.AutoSize = true;
        urlValue.Location = new Point(110, 42);
        urlValue.Size = new Size(450, 20);

        firewallLabel.Text = "Firewall";
        firewallLabel.Location = new Point(12, 69);
        firewallLabel.AutoSize = true;
        firewallValue.Location = new Point(110, 69);
        firewallValue.Size = new Size(450, 20);

        networkProfileLabel.Text = "Network profile";
        networkProfileLabel.Location = new Point(12, 96);
        networkProfileLabel.AutoSize = true;
        networkProfileValue.Location = new Point(150, 96);
        networkProfileValue.Size = new Size(410, 20);

        portListeningLabel.Text = "Port";
        portListeningLabel.Location = new Point(12, 123);
        portListeningLabel.AutoSize = true;
        portListeningValue.Location = new Point(150, 123);
        portListeningValue.Size = new Size(410, 20);

        firewallSetupLabel.Text = "Firewall setup";
        firewallSetupLabel.Location = new Point(12, 150);
        firewallSetupLabel.AutoSize = true;
        firewallSetupValue.Location = new Point(150, 150);
        firewallSetupValue.Size = new Size(410, 20);

        warningLabel.ForeColor = Color.Firebrick;
        warningLabel.Location = new Point(12, 177);
        warningLabel.Size = new Size(548, 24);

        retryLabel.Text = "Retry diagnostics";
        retryLabel.Location = new Point(12, 207);
        retryLabel.AutoSize = true;
        retryValue.Location = new Point(150, 207);
        retryValue.Size = new Size(80, 20);

        durationLabel.Text = "Duration";
        durationLabel.Location = new Point(12, 239);
        durationLabel.AutoSize = true;
        durationComboBox.DropDownStyle = ComboBoxStyle.DropDownList;
        durationComboBox.Location = new Point(110, 235);
        durationComboBox.Size = new Size(160, 28);

        interfaceLabel.Text = "Interface";
        interfaceLabel.Location = new Point(300, 239);
        interfaceLabel.AutoSize = true;
        interfaceComboBox.DropDownStyle = ComboBoxStyle.DropDownList;
        interfaceComboBox.Location = new Point(370, 235);
        interfaceComboBox.Size = new Size(190, 28);

        pairingUrlLabel.Text = "Pairing";
        pairingUrlLabel.Location = new Point(12, 277);
        pairingUrlLabel.AutoSize = true;
        pairingUrlValue.Location = new Point(110, 277);
        pairingUrlValue.Size = new Size(320, 42);
        qrPictureBox.BorderStyle = BorderStyle.FixedSingle;
        qrPictureBox.Location = new Point(446, 271);
        qrPictureBox.Size = new Size(114, 114);
        qrPictureBox.SizeMode = PictureBoxSizeMode.Zoom;

        browserListLabel.Text = "Paired browser authorizations";
        browserListLabel.Location = new Point(12, 377);
        browserListLabel.AutoSize = true;
        browserListBox.Location = new Point(12, 401);
        browserListBox.Size = new Size(260, 104);
        sharedListBox.Location = new Point(300, 401);
        sharedListBox.Size = new Size(260, 104);
        pendingListBox.Location = new Point(12, 541);
        pendingListBox.Size = new Size(548, 84);

        startButton.Text = "Start";
        startButton.Location = new Point(12, 646);
        startButton.Size = new Size(75, 30);
        stopButton.Text = "Stop";
        stopButton.Location = new Point(93, 646);
        stopButton.Size = new Size(75, 30);
        pairButton.Text = "Pair";
        pairButton.Location = new Point(174, 646);
        pairButton.Size = new Size(75, 30);
        revokeButton.Text = "Revoke";
        revokeButton.Location = new Point(255, 646);
        revokeButton.Size = new Size(82, 30);
        revokeAllButton.Text = "Revoke all";
        revokeAllButton.Location = new Point(343, 646);
        revokeAllButton.Size = new Size(92, 30);
        exitButton.Text = "Exit";
        exitButton.Location = new Point(485, 646);
        exitButton.Size = new Size(75, 30);

        withdrawButton.Text = "Withdraw shared";
        withdrawButton.Location = new Point(300, 511);
        withdrawButton.Size = new Size(130, 28);
        allowButton.Text = "Allow once";
        allowButton.Location = new Point(12, 631);
        allowButton.Size = new Size(105, 28);
        discardButton.Text = "Discard";
        discardButton.Location = new Point(123, 631);
        discardButton.Size = new Size(95, 28);

        ClientSize = new Size(580, 691);
        Controls.Add(serviceStatusLabel);
        Controls.Add(serviceStatusValue);
        Controls.Add(urlLabel);
        Controls.Add(urlValue);
        Controls.Add(firewallLabel);
        Controls.Add(firewallValue);
        Controls.Add(networkProfileLabel);
        Controls.Add(networkProfileValue);
        Controls.Add(portListeningLabel);
        Controls.Add(portListeningValue);
        Controls.Add(firewallSetupLabel);
        Controls.Add(firewallSetupValue);
        Controls.Add(warningLabel);
        Controls.Add(retryLabel);
        Controls.Add(retryValue);
        Controls.Add(durationLabel);
        Controls.Add(durationComboBox);
        Controls.Add(interfaceLabel);
        Controls.Add(interfaceComboBox);
        Controls.Add(pairingUrlLabel);
        Controls.Add(pairingUrlValue);
        Controls.Add(qrPictureBox);
        Controls.Add(browserListLabel);
        Controls.Add(browserListBox);
        Controls.Add(sharedListBox);
        Controls.Add(pendingListBox);
        Controls.Add(startButton);
        Controls.Add(stopButton);
        Controls.Add(pairButton);
        Controls.Add(revokeButton);
        Controls.Add(revokeAllButton);
        Controls.Add(withdrawButton);
        Controls.Add(allowButton);
        Controls.Add(discardButton);
        Controls.Add(exitButton);
        MaximizeBox = false;
        Text = "Universal Clipboard";
        ResumeLayout(false);
        PerformLayout();
    }
}
