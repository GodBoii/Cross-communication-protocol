using CCP.Windows.Models;
using CCP.Windows.Services;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;

namespace CCP.Windows;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly CcpNode _node;
    private PeerView? _selectedPeer;
    private bool _isLoadingPanel;
    private string _selectedPeerLabel = "No device selected";
    private string _panelTitle = "Choose a trusted device";
    private string _panelSubtitle = "Pair with an Android phone, then load its device panel from the desktop app.";
    private string _batteryText = "Unknown";
    private string _storageText = "Unknown";
    private string _notificationAccessText = "Unknown";
    private string _galleryAccessText = "Unknown";

    public ObservableCollection<PeerView> Peers { get; } = [];
    public ObservableCollection<string> Events { get; } = [];
    public ObservableCollection<RemoteFactView> DeviceSettings { get; } = [];
    public ObservableCollection<RemoteContentItem> GalleryItems { get; } = [];
    public ObservableCollection<RemoteContentItem> FileItems { get; } = [];
    public ObservableCollection<RemoteContentItem> NotificationItems { get; } = [];

    public ICommand PairCommand { get; }
    public ICommand SendFileCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand RefreshPanelCommand { get; }

    public string LocalStatus => "Bridge online";
    public string FooterStatus { get; private set; } = "Starting native Windows node...";

    public PeerView? SelectedPeer
    {
        get => _selectedPeer;
        set
        {
            _selectedPeer = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsPeerSelected));
            SelectedPeerLabel = value is null
                ? "No device selected"
                : $"{value.DeviceName}  {value.Platform}  {value.Address}:{value.TcpPort}";
            _ = LoadPeerPanelAsync();
        }
    }

    public bool IsPeerSelected => SelectedPeer is not null;

    public bool IsLoadingPanel
    {
        get => _isLoadingPanel;
        set { _isLoadingPanel = value; OnPropertyChanged(); }
    }

    public string SelectedPeerLabel
    {
        get => _selectedPeerLabel;
        set { _selectedPeerLabel = value; OnPropertyChanged(); }
    }

    public string PanelTitle
    {
        get => _panelTitle;
        set { _panelTitle = value; OnPropertyChanged(); }
    }

    public string PanelSubtitle
    {
        get => _panelSubtitle;
        set { _panelSubtitle = value; OnPropertyChanged(); }
    }

    public string BatteryText
    {
        get => _batteryText;
        set { _batteryText = value; OnPropertyChanged(); }
    }

    public string StorageText
    {
        get => _storageText;
        set { _storageText = value; OnPropertyChanged(); }
    }

    public string NotificationAccessText
    {
        get => _notificationAccessText;
        set { _notificationAccessText = value; OnPropertyChanged(); }
    }

    public string GalleryAccessText
    {
        get => _galleryAccessText;
        set { _galleryAccessText = value; OnPropertyChanged(); }
    }

    public MainWindow()
    {
        InitializeComponent();

        _node = new CcpNode(
            onPeers: peers => Dispatcher.Invoke(() =>
            {
                var selectedId = SelectedPeer?.DeviceId;
                Peers.Clear();
                foreach (var peer in peers) Peers.Add(peer);
                if (selectedId is not null)
                {
                    SelectedPeer = Peers.FirstOrDefault(p => p.DeviceId == selectedId);
                }
            }),
            onEvent: message => Dispatcher.Invoke(() =>
            {
                Events.Insert(0, message);
                while (Events.Count > 100) Events.RemoveAt(Events.Count - 1);
                FooterStatus = message;
                OnPropertyChanged(nameof(FooterStatus));
            }),
            confirm: (title, message) => Dispatcher.Invoke(() =>
                MessageBox.Show(this, message, title, MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes));

        PairCommand = new RelayCommand<PeerView>(peer => _ = PairPeerAsync(peer), peer => peer is not null);
        SendFileCommand = new RelayCommand<PeerView>(SendFile, peer => peer?.Trusted == true);
        RefreshCommand = new RelayCommand<object>(_ => _node.BroadcastNow());
        RefreshPanelCommand = new RelayCommand<object>(_ => _ = LoadPeerPanelAsync(), _ => SelectedPeer?.Trusted == true);
        DataContext = this;

        Loaded += async (_, _) => await _node.StartAsync();
        Closing += (_, _) => _node.Dispose();
    }

    private async Task PairPeerAsync(PeerView? peer)
    {
        if (peer is null) return;
        await _node.PairAsync(peer);
        await LoadPeerPanelAsync();
    }

    private void SendFile(PeerView? peer)
    {
        if (peer is null) return;
        var picker = new OpenFileDialog { Title = "Choose file to send" };
        if (picker.ShowDialog(this) == true)
        {
            _ = _node.SendFileAsync(peer, picker.FileName);
        }
    }

    private async Task LoadPeerPanelAsync()
    {
        var peer = SelectedPeer;
        if (peer is null)
        {
            ResetPanel();
            return;
        }

        if (!peer.Trusted)
        {
            ResetPanel(peer.DeviceName, "Pair with this device to browse gallery, files, notifications, and settings.");
            return;
        }

        IsLoadingPanel = true;
        try
        {
            var panel = await _node.GetPeerPanelAsync(peer);
            PanelTitle = panel.Title;
            PanelSubtitle = panel.Subtitle;
            BatteryText = panel.Battery;
            StorageText = panel.Storage;
            NotificationAccessText = panel.NotificationAccess;
            GalleryAccessText = panel.GalleryAccess;

            Replace(DeviceSettings, panel.Settings);
            Replace(GalleryItems, panel.Gallery);
            Replace(FileItems, panel.Files);
            Replace(NotificationItems, panel.Notifications);
        }
        catch (Exception ex)
        {
            FooterStatus = $"Failed to load device panel: {ex.Message}";
            OnPropertyChanged(nameof(FooterStatus));
        }
        finally
        {
            IsLoadingPanel = false;
        }
    }

    private void ResetPanel(string title = "Choose a trusted device", string subtitle = "Pair with an Android phone, then load its device panel from the desktop app.")
    {
        PanelTitle = title;
        PanelSubtitle = subtitle;
        BatteryText = "Unknown";
        StorageText = "Unknown";
        NotificationAccessText = "Unknown";
        GalleryAccessText = "Unknown";
        Replace(DeviceSettings, []);
        Replace(GalleryItems, []);
        Replace(FileItems, []);
        Replace(NotificationItems, []);
    }

    private static void Replace<T>(ObservableCollection<T> target, IReadOnlyList<T> source)
    {
        target.Clear();
        foreach (var item in source) target.Add(item);
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}

