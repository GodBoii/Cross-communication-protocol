using System.Windows.Input;

namespace CCP.Windows.Services;

public sealed class RelayCommand<T>(Action<T?> execute, Predicate<T?>? canExecute = null) : ICommand
{
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => canExecute?.Invoke((T?)parameter) ?? true;
    public void Execute(object? parameter) => execute((T?)parameter);
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

