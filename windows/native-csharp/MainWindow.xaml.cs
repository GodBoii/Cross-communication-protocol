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

    public ObservableCollection<PeerView> Peers { get; } = [];
    public ObservableCollection<string> Events { get; } = [];
    public ICommand PairCommand { get; }
    public ICommand SendFileCommand { get; }
    public ICommand RefreshCommand { get; }

    public string LocalStatus => "Discovery active";
    public string FooterStatus { get; private set; } = "Starting native Windows node...";

    public PeerView? SelectedPeer
    {
        get => _selectedPeer;
        set { _selectedPeer = value; OnPropertyChanged(); }
    }

    public MainWindow()
    {
        InitializeComponent();

        _node = new CcpNode(
            onPeers: peers => Dispatcher.Invoke(() =>
            {
                Peers.Clear();
                foreach (var peer in peers) Peers.Add(peer);
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

        PairCommand = new RelayCommand<PeerView>(peer => _ = _node.PairAsync(peer!), peer => peer is not null);
        SendFileCommand = new RelayCommand<PeerView>(SendFile, peer => peer?.Trusted == true);
        RefreshCommand = new RelayCommand<object>(_ => _node.BroadcastNow());
        DataContext = this;

        Loaded += async (_, _) => await _node.StartAsync();
        Closing += (_, _) => _node.Dispose();
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

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
