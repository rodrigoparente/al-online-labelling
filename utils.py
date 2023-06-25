# python imports
import os


def abs_base_path(relative_path=''):
    return os.path.join(os.environ.get('base_dir'), relative_path)


def abs_results_path(relative_path=''):
    return os.path.join(os.environ.get('results_path'), relative_path)


def clear_window():
    os.system('cls' if os.name == 'nt' else 'clear')